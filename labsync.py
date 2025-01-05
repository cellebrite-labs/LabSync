from __future__ import annotations

import configparser
import contextlib
import dataclasses
import functools
import io
import logging
import os
import pathlib
import re
import string
import tempfile
import time
import uuid
from collections.abc import Generator
from typing import IO, Any, Optional

import git
import parse
import yaml

try:
    import functioninliner
except ModuleNotFoundError:
    # define a mock that will allow us to work without functioninliner installed
    class functioninliner:  # noqa: N801
        class ClonesStorage(dict):
            def update_from_storage(self) -> None:
                pass

try:
    import ida_diskio
    import ida_idaapi
    import ida_idp
    import ida_kernwin
    import ida_loader
    import ida_nalt
    import ida_name
    import ida_segment
    import ida_typeinf
    import ida_xref
    import idautils
    import netnode
    import sark
except ModuleNotFoundError:
    # define mocks to support importing outside of IDA for testing
    class ida_kernwin:  # noqa: N801
        class action_handler_t:  # noqa: N801
            pass

        class UI_Hooks:  # noqa: N801
            pass

    class ida_idaapi:  # noqa: N801
        PLUGIN_MOD = 0
        PLUGIN_HIDE = 0

        class plugin_t:  # noqa: N801
            pass

    class ida_idp:  # noqa: N801
        IDP_INTERFACE_VERSION = 0

    class ida_typeinf:  # noqa: N801
        class text_sink_t:  # noqa: N801
            pass

        class tinfo_t:  # noqa: N801
            pass

    class netnode:  # noqa: N801
        class Netnode:
            pass


# CONFIGURATION


# we decided not to normalize prototypes because it makes it much harder to resolve conflicts since
# you don't know which function you're looking at
#
# the downside is that a conflict on a function name change will result in two conflicts (one on
# the name and one on the prototype)
NORMALIZE_PROTOTYPES = False

LOCAL_TYPES_COMMENT_FMT = "/* >> LABSYNC DO NOT TOUCH: {} << */"

LOCKFILE = "labsync.lock"
DEFAULT_LOCK_TIMEOUT = 60  # sec


# LOGGING


class LoggerWithTrace(logging.getLoggerClass()):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        logging.TRACE = 5
        logging.addLevelName(logging.TRACE, "TRACE")

    def trace(self, msg: str, *args, **kwargs) -> None:
        self.log(logging.TRACE, msg, *args, **kwargs)


logger = LoggerWithTrace("LabSync")


# EXCEPTIONS


class LabSyncError(Exception):
    pass


class LabSyncLockError(LabSyncError):
    pass


class LabSyncBinaryMatchingError(LabSyncError):
    pass


# HELPERS


class LabSyncYAMLDumper(yaml.CDumper):
    @staticmethod
    def _hex_representer(dumper: yaml.Dumper, data: int) -> str:
        return dumper.represent_scalar("tag:yaml.org,2002:int", hex(data))

    @staticmethod
    def _str_representer(dumper: yaml.dumper, data: str) -> str:
        if "\n" in data:
            return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
        else:
            return dumper.represent_scalar("tag:yaml.org,2002:str", data)


LabSyncYAMLDumper.add_representer(int, LabSyncYAMLDumper._hex_representer)  # noqa: SLF001
LabSyncYAMLDumper.add_representer(str, LabSyncYAMLDumper._str_representer)  # noqa: SLF001


@contextlib.contextmanager
def wait_box(msg: str, *, hide_cancel: bool = False) -> None:
    prefix = "HIDECANCEL\n" if hide_cancel else ""
    ida_kernwin.show_wait_box(prefix + msg)
    try:
        yield None
    finally:
        ida_kernwin.hide_wait_box()


class StringIOTextSink(ida_typeinf.text_sink_t):
    def __init__(self):
        super().__init__()
        self.sio = io.StringIO()

    def _print(self, thing: str) -> int:
        self.sio.write(thing)
        return 0


def local_types() -> Generator[str]:
    name = ida_typeinf.first_named_type(None, ida_typeinf.NTF_TYPE)
    while name:
        yield name
        name = ida_typeinf.next_named_type(None, name, ida_typeinf.NTF_TYPE)


# EXPORT LOGIC


@dataclasses.dataclass(eq=True, order=True)
class SyncedBinary:
    idb_id: str = dataclasses.field(compare=False)
    start_ea: int = 0  # must be the first field, because we rely on it when sorting
    end_ea: int = ida_idaapi.BADADDR  # exclusive
    base_ea: int = 0
    seg_prefix: Optional[str] = None

    def contains(self, ea: int) -> bool:
        return self.start_ea <= ea < self.end_ea

    def ea2dump(self, ea: int) -> int:
        return ea - self.base_ea

    def dump2ea(self, dea: int) -> int:
        return dea + self.base_ea


def dump_names(binary: SyncedBinary, storage: functioninliner.ClonesStorage) -> dict[int, str]:
    d = {}
    for ea, name in idautils.Names():
        if not binary.contains(ea):
            continue

        seg = ida_segment.getseg(ea)
        seg_name = ida_segment.get_segm_name(seg)

        # skip names that are in inlined chunks
        if seg_name.startswith("inlined_"):
            continue

        # skip names for inlined functions
        if ea in storage:
            continue

        dea = binary.ea2dump(ea)
        d[dea] = name

    return d


def dump_inlined_funcs(binary: SyncedBinary, storage: functioninliner.ClonesStorage) -> list[int]:
    funcs = (binary.ea2dump(ea) for ea in storage if binary.contains(ea))
    return list(sorted(funcs))  # noqa: C413


def dump_local_types(types: netnode.Netnode) -> str:
    sio = io.StringIO()

    # we emulate print_decls() ourselves because it internally uses PRTYPE_NOREGEX and this
    # removes namespaces which starts with double underscore (e.g. std::__1::__libcpp_refstring)
    tinfo = ida_typeinf.tinfo_t()
    for ordinal in range(1, ida_typeinf.get_ordinal_qty(None)):
        if not tinfo.get_numbered_type(None, ordinal):
            continue  # deleted ordinal

        name = tinfo.get_type_name()

        flags = (
            ida_typeinf.PRTYPE_MULTI |  # multiline
            ida_typeinf.PRTYPE_TYPE |  # required to have it named
            ida_typeinf.PRTYPE_PRAGMA |  # include alignment pragmas
            ida_typeinf.PRTYPE_SEMI |  # end with semicolon
            ida_typeinf.PRTYPE_CPP |  # unsure if this is needed, but to be on the safe side...
            ida_typeinf.PRTYPE_DEF |  # required to have a full definition
            ida_typeinf.PRTYPE_NOREGEX  # required to keep the name as-is
        )

        decl = ida_typeinf.print_tinfo(None, 2, 0, flags, tinfo, name, None)

        # IDA apparently can't handle templates in parse_decls(), so we we don't bother syncing
        # them at all. hopefully no sane reverser actually uses them and these are only imported
        # from debug symbols and never touched
        if "<" in strip_comments(decl):
            logger.debug(
                f"skipping syncing of local type {name!r} because templates are unsupported"  # noqa: COM812
            )
            continue

        sio.write(f"/* {ordinal} */\n")
        sio.write(decl)
        sio.write("\n")

    hdr = sio.getvalue()

    # now that we don't use print_decls() we don't really have to use decl_to_name_and_type() in
    # normalize_local_types() in this flow, but we prefer to in order to fail early if there's any
    # bug there, before we commit it to the repo
    return normalize_local_types(hdr, types)


def strip_comments(decl: str) -> str:
    stripped_lines = []

    for line in decl.splitlines():
        try:
            line = line[:line.index("//")].rstrip()
            if not line:
                continue
        except ValueError:
            pass
        stripped_lines.append(line)

    return "\n".join(stripped_lines)


@functools.cache
def decl_to_type_name_pat() -> re.Pattern:
    """this generates a pattern that tries to match the first line of a (stripped) decl to the
    its type (e.g. struct/union/typedef) and name

    the regex matches 2N groups where group 2i is "type" and group 2i+1 is name, for different
    possible subregexes. Only 2 groups (for some i) should be matched

    this regex is a bit more "allowing" than how IDA formats decls, since we also use it to
    match decls from YAMLs in which the user might've changed some whitespacing while manually
    resolving a merge conflict
    """

    # from ida.cfg:TypeNameChars
    name_chars = r"_:$()`'{}" + string.digits + string.ascii_letters
    # from blackbox testing what's allowed from name_chars as the first character
    name_first_chars = r"_$`" + string.ascii_letters

    name_pat = r"([" + re.escape(name_first_chars) + "][" + re.escape(name_chars) + "]*?)"

    type_pat = (
        r"(?!typedef)(\S+)(?=\s)"  # only match non-typedefs
        r".*?\s" +  # everything up to the name (i.e. type + attributes)
        name_pat +
        r"(?:\s*(?<!:):(?!:).*)?"  # optional inheritance or IDA syntax for data types of enums
        r"\s*;?"  # optional semicolon in case of forward declarations
    )

    fptr_typedef_pat = (
        r"(typedef)(?=\s)"  # only match typdefs
        r".*?"  # everything up to the name
        r"\*\s*" +  # the star before the name
        name_pat +
        r"\s*\)\(.*"  # match the first function def in the line, in case there is also a fptr arg
        r".*;"  # everything else
    )

    norm_typedef_pat = (
        r"(typedef)(?=\s)"  # only match typdefs
        r".*?"  # everything up to the name
        r"\**" +  # optional stars before the name
        name_pat +
        r"(?:\s*\[\s*\d*\s*\])?"  # optional array part
        r"\s*;"  # end of the typedef
    )

    pat = (
        r"^(?:"  # start of line
            r"(?:" + type_pat + ")"
        r"|"
            r"(?:" + fptr_typedef_pat + ")"
        r"|"
            r"(?:" + norm_typedef_pat + ")"
        r")$"  # end of line
    )

    return re.compile(pat)


def decl_to_name_and_type(decl: str) -> tuple[str, str]:
    # skip pragma/comment lines
    for first_line in decl.splitlines():
        if not any(first_line.lstrip().startswith(x) for x in ("#", "//")):
            break
    else:
        msg = f"empty local type:\n{decl}"
        raise LabSyncError(msg)

    # strip the first line
    first_line = first_line.strip()

    # extract the name and decl type
    pat = decl_to_type_name_pat()
    m = pat.match(first_line)

    if not m:
        msg = f"failed to parse local type:\n{decl}"
        raise LabSyncError(msg)

    decl_type = m.group(m.lastindex - 1)
    name = m.group(m.lastindex)
        # should never happen according to our regex
    assert decl_type
    assert name

    return name, decl_type


def normalize_local_types(
    hdr: str, types: netnode.Netnode, split_pat: Optional[str] = None,
) -> str:

    # remove warnings for removed types
    hdr = re.sub(r"^/\* WARNING: no name found for type \d+ \*/$", "", hdr, flags=re.MULTILINE)

    # split according to comments IDA adds with the numerals of local types
    if split_pat is None:
        split_pat = r"^/\* \d+ \*/$"
    parts = re.split(split_pat, hdr, flags=re.MULTILINE)

    if parts[0].strip():
        msg = f"found unexpected forward declarations:\n{parts[0].strip()}"
        raise LabSyncError(msg)

    # parse type declaration names
    decls = {}
    for decl in parts[1:]:
        decl = decl.strip()
        # also strip trailing spaces since they arn't block-encodable in YAML
        decl = "\n".join(line.rstrip() for line in decl.splitlines())

        # TODO @TH: there is an IDA bug where comment-only changes to local types are not updated
        #           when using parse_decls() so for now we just strip all comments until it'll be
        #           fixed
        decl = strip_comments(decl)

        # TODO @TH: we should be able to remove this now that we added the uuid comments
        #
        # make sure that the decleration doesn't contain empty lines since we depend on that in
        # the update logic
        #
        # we though about replacing it with a marker before each local type declaration, but then
        # we said that in complex conflicts people may not restore them to how we expect so that
        # might come out worse
        #
        # and anyway we expect people not to modify other stuff either (e.g. the structure of the
        # first line of the local type)
        if "\n\n" in decl:
            msg = f"found declaration with unexpected empty line:\n{decl}"
            raise LabSyncError(msg)

        # extract the name of the type
        name, _ = decl_to_name_and_type(decl)

        # make sure it's unique
        if name in decls:
            msg = (
                f"found two local type declarations with the same name:\n{decls[name]}\n"
                f"and:\n{decl}"
            )
            raise LabSyncError(msg)

        # add uuid
        tid = ida_typeinf.get_named_type_tid(name)
        if tid == ida_idaapi.BADADDR:
            msg = f"failed to resolve tid of local type {name!r}:\n{decl}"
            raise LabSyncError(msg)
        decl_uuid = types.get(tid)
        if not decl_uuid:
            types[tid] = decl_uuid = str(uuid.uuid4())

        decls[name] = (decl_uuid, decl)

    # generate the normalized local types
    nhdr = io.StringIO()

    for _, (decl_uuid, decl) in sorted(decls.items()):
        nhdr.write(LOCAL_TYPES_COMMENT_FMT.format(decl_uuid))
        nhdr.write("\n")
        nhdr.write(decl)
        nhdr.write("\n\n")

    return nhdr.getvalue().strip()


def fix_non_present_arguments(name: str, tinfo: ida_typeinf.tinfo_t, *, add: bool = True) \
        -> tuple[ida_typeinf.tinfo_t, bool]:

    def type_exists(tinfo: ida_typeinf.tinfo_t) -> bool:
        if tinfo.present():
            return True

        # originally we used just tinfo.present(), but for some reason it keeps returning False
        # even after we saved the type (as a forward declaration)
        #
        # then we used tinfo.get_ordinal() > 0 as a test, but on huge IDBs with >10k types, for
        # some reason it kept returning 0 even after we saved the type
        #
        # therefore we moved to checking if we can get the tid for the type name. you have to watch
        # out, however, since for deleted types tinfo.get_type_name() raises UnicodeDecodeError
        try:
            tname = tinfo.get_type_name()
        except UnicodeDecodeError:
            return False

        tid = ida_typeinf.get_named_type_tid(tname)
        return tid != ida_idaapi.BADADDR

    def fix_non_present(tinfo: ida_typeinf.tinfo_t) -> tuple[ida_typeinf.tinfo_t, bool]:
        tinfo_orig = tinfo.copy()

        # deref pointer/array until we reach the actual type
        depth = 0
        while depth < 128:
            if not tinfo.remove_ptr_or_array():
                break
            depth += 1
        else:
            msg = "max pointer depth reached"
            raise LabSyncError(msg)

        # if we're allowed to and this type is missing, add its base to local types
        if not type_exists(tinfo) and add:
            # add the type to local types
            if tinfo.save_type() == 0:
                tname = tinfo.get_type_name()

                logger.warning(
                    f"the prototype for {name} used type {tname} that was not present in the TIL. "
                    "we silently added it to allow syncing"  # noqa: COM812
                )

                return tinfo_orig, False
            else:
                # we can't use tname for deleted types (it raises UnicodeDecodeError)
                tinfo_clean = tinfo.copy()
                tinfo_clean.set_modifiers(0)
                tname = tinfo_clean.dstr()

                logger.warning(
                    f"the prototype for {name} used type {tname} that was not present in the TIL. "
                    "we failed to silently add it to allow syncing (perhaps a deleted type?)"  # noqa: COM812
                )

        # TODO @TH: IDA has a bug where they can't parse _BOOL8 args, so we replace them.
        #           remove this flow after they fix it
        bool8_realtype = ida_typeinf.BT_BOOL | ida_typeinf.BTMT_BOOL8
        if tinfo.get_realtype() == bool8_realtype:
            pass
        elif type_exists(tinfo):
            # if it's real present type, we're good
            return tinfo_orig, False

        # replace the type with an unknown type
        tinfo_generic = ida_typeinf.tinfo_t()
        assert tinfo_generic.create_simple_type(ida_typeinf.BT_UNKNOWN)

            # set the original modifiers
        tinfo_generic.set_modifiers(tinfo.get_modifiers())

            # recrate the pointer depth on top of tinfo_generic
        for _ in range(depth):
            assert tinfo_generic.create_ptr(tinfo_generic)

        return tinfo_generic, True

    ftype = ida_typeinf.func_type_data_t()
    assert tinfo.get_func_details(ftype, ida_typeinf.GTD_NO_ARGLOCS)

    ftype.rettype, fixed = fix_non_present(ftype.rettype)
    for i, argtype in enumerate(ftype):
        ftype[i].type, arg_fixed = fix_non_present(argtype.type)
        fixed |= arg_fixed

    tinfo_new = ida_typeinf.tinfo_t()
    assert tinfo_new.create_func(ftype)

    return tinfo_new, fixed


def prototype(ea: int) -> str:
    tinfo = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tinfo, ea):
        return None

    name = ida_name.get_ea_name(ea, ida_name.GN_VISIBLE)

    # replace non-present arguments in the prototype if relevant
    tinfo_new, fixed = fix_non_present_arguments(name, tinfo)

    if fixed:
        ptype = ida_typeinf.print_tinfo(None, 0, 0, ida_typeinf.PRTYPE_1LINE, tinfo, None, None)
        new_ptype = ida_typeinf.print_tinfo(None, 0, 0, ida_typeinf.PRTYPE_1LINE, tinfo_new, None,
                                            None)
        logger.warning(
            f"replacing prototype for {name} because it uses types that are not present in the "
            f"TIL from:\n\t{ptype!r}\nto:\n\t{new_ptype!r}"  # noqa: COM812
        )

        if not ida_nalt.set_tinfo(ea, tinfo_new):
            logger.warning(f"failed setting new prototype for {name}! skipping it")
            return None

        tinfo = tinfo_new

    # generate the prototype to dump
    if NORMALIZE_PROTOTYPES:
        name = "FUNCTION"

    # we have to remove special characters from the name, otherwise we'll have an issue applying
    # the prototype afterwards (e.g. `__Foo.cxx_destruct_`)
    allowed = r"_$" + string.digits + string.ascii_letters
    pname = "".join(c if c in allowed else "_" for c in name)
    return ida_typeinf.print_tinfo(None, 0, 0, ida_typeinf.PRTYPE_1LINE, tinfo, pname, None)


def dump_prototypes(
    binary: SyncedBinary, storage: functioninliner.ClonesStorage) -> dict[int, str]:

    d = {}
    for ea in idautils.Functions():
        if not binary.contains(ea):
            continue

        seg = ida_segment.getseg(ea)
        seg_name = ida_segment.get_segm_name(seg)

        # skip funcs that are in inlined chunks somehow (shouldn't happen)
        if seg_name.startswith("inlined_"):
            continue

        # skip funcs that have been inlined
        if ea in storage:
            continue

        ptype = prototype(ea)
        if ptype:
            dea = binary.ea2dump(ea)
            d[dea] = ptype

    return d


def dump(binary: SyncedBinary, types: netnode.Netnode) -> str:
    storage = functioninliner.ClonesStorage()
    storage.update_from_storage()

    d = {
        "version": 4,
        "names": dump_names(binary, storage),
        "inlined_funcs": dump_inlined_funcs(binary, storage),
        # we have to dump prototypes before we dump local types because this may add new types to
        # the TIL
        "prototypes": dump_prototypes(binary, storage),
        "local_types": dump_local_types(types),
    }

    return yaml.dump(
        d, Dumper=LabSyncYAMLDumper, default_flow_style=False, sort_keys=True,
    )


# IMPORT LOGIC


def update_names(
    binary: SyncedBinary, storage: functioninliner.ClonesStorage, names: dict[int, str]) -> None:

    # delete names if required
    for dea in dump_names(binary, storage):
        # delete name if unnamed in the new dict
        if dea not in names:
            ea = binary.dump2ea(dea)

            msg = f"removing name from {ea:#x}"
            logger.debug(msg)

            success = ida_name.set_name(ea, "", ida_name.SN_NOWARN)
            if not success:
                if logger.getEffectiveLevel() > logging.DEBUG:
                    logger.warning("failed " + msg)
                else:
                    logger.warning("removal failed!")

    # update names
    for dea, name in names.items():
        ea = binary.dump2ea(dea)
        cur_name = ida_name.get_name(ea)

        if cur_name != name:
            msg = f"renaming {ea:#x} from {cur_name!r} to {name!r}"
            logger.debug(msg)

            # check if the new name already exists in the database
            cur_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
            name_changed = False
            try:
                # if the new name is already in use in the IDB --
                if cur_ea != ida_idaapi.BADADDR:
                    # verify that the repo also has a different name for the EA currently holding
                    # the new name
                    #
                    # perhaps we can even assert that this never happens
                    cur_dea = binary.ea2dump(cur_ea)
                    if cur_dea not in names:
                        logger.warning(
                            f"cannot rename {ea:#x} to {name!r} as this name already "
                            f"exists in the IDB for {cur_ea:#x}, and that EA doesn't "
                            "have a different name in the repo"  # noqa: COM812
                        )
                        continue

                    # temporarily rename it to something else
                    msg2 = f"temporarily renaming {cur_ea:#x} away from {name!r}"
                    logger.debug("\t" + msg2)
                    success = ida_name.set_name(
                        cur_ea,
                        name + "_labsync_temp",
                        ida_name.SN_NOWARN | ida_name.SN_FORCE,
                    )

                    # handle temporary rename failure
                    if not success:
                        if logger.getEffectiveLevel() > logging.DEBUG:
                            logger.warning("failed " + msg2)
                        else:
                            logger.warning("\ttemporary rename failed!")
                        continue

                # now do the actual rename
                success = ida_name.set_name(ea, name, ida_name.SN_NOWARN)

                # handle rename failure
                if not success:
                    if logger.getEffectiveLevel() > logging.DEBUG:
                        logger.warning("failed " + msg)
                    else:
                        logger.warning("rename failed!")
                    continue

                name_changed = True
            finally:
                # if we failed, undo the temporary rename if we did any
                if cur_ea != ida_idaapi.BADADDR and not name_changed:
                    msg2 = f"undoing the temporarily rename of {cur_ea:#x}"
                    logger.debug("\t" + msg2)
                    success = ida_name.set_name(cur_ea, name, ida_name.SN_NOWARN)

                    # handle temporary rename undoing failure
                    if not success:
                        if logger.getEffectiveLevel() > logging.DEBUG:
                            logger.warning("failed " + msg2)
                        else:
                            logger.warning("\ttemporary rename undoing failed!")


def update_inlined_funcs(
    binary: SyncedBinary, storage: functioninliner.ClonesStorage, funcs: list[int]) -> None:

    cur = {ea for ea in storage if binary.contains(ea)}
    new = set(map(binary.dump2ea, funcs))

    undo = cur - new
    do = new - cur

    for ea in undo:
        func = sark.Function(ea)
        if func.ea != ea:
            logger.warning(f"\tcannot undo inlining of {ea:#x} since it's not a function start!")
            continue
        msg = f"undoing inlining of {func.name}"
        logger.debug(msg)
        functioninliner.undo_inline_function(func)

    for ea in do:
        func = sark.Function(ea)
        if func.ea != ea:
            logger.warning(
                f"not inlining function @ {ea:#x} since it's not a function start"  # noqa: COM812
            )
        logger.debug(f"inlining {func.name}")
        functioninliner.inline_function(func)


def _rename_local_type(tid: int, name: str) -> tuple[int, str]:
    """note: if name is in use by another local type, that local type will be removed"""

    ordinal = ida_typeinf.get_tid_ordinal(tid)
    assert ordinal

    tinfo = ida_typeinf.tinfo_t()
    assert tinfo.get_numbered_type(None, ordinal)

    # TODO  @TH: perhaps tinfo.rename_type can be used instead? found out about it later
    err = tinfo.set_numbered_type(None, ordinal, ida_typeinf.NTF_REPLACE, name)
    errstr = ida_typeinf.tinfo_errstr(err)
    return err, errstr


def rename_local_type(
    cur_name: str, name: str, types: netnode.Netnode, uuids: dict[int, str],
) -> None:

    msg = f"renaming local type {cur_name!r} to {name!r}"
    logger.debug(msg)

    # resolve the type we're changing
    tid = ida_typeinf.get_named_type_tid(cur_name)
    assert tid != ida_idaapi.BADADDR

    # check if the new name is in use
    cur_tid = ida_typeinf.get_named_type_tid(name)
    name_changed = False
    try:
        # if the new name is already in use in the IDB --
        if cur_tid != ida_idaapi.BADADDR:
            # assert that the repo also has a different name for the type currently holding the new
            # name
            #
            # this is an assertion because if it's missing from the repo we should've already
            # deleted it
            #
            # also, we don't actually verify that the name since we already verified beforehand
            # that there are no duplicate names
            cur_uuid = types[cur_tid]
            assert cur_uuid in uuids

            # temporarily rename it to something else
            msg2 = f"temporarily renaming local type {name!r}"
            logger.debug("\t" + msg2)
            err, errstr = _rename_local_type(cur_tid, name + "_labsync_temp")

            # handle temporary rename failure
            if err:
                if logger.getEffectiveLevel() > logging.DEBUG:
                    logger.warning("failed " + msg2 + f": {errstr}")
                else:
                    logger.warning(f"\ttemporary rename failed: {errstr}")
                return False

        # now do the actual rename
        err, errstr = _rename_local_type(tid, name)

        # handle rename failure
        if err:
            if logger.getEffectiveLevel() > logging.DEBUG:
                logger.warning("failed " + msg + f": {errstr}")
            else:
                logger.warning(f"rename failed: {errstr}")
            return False

        name_changed = True
    finally:
        # if we failed, undo the temporary rename if we did any
        if cur_tid != ida_idaapi.BADADDR and not name_changed:
            msg2 = f"undoing the temporarily rename of local type {name!r}"
            logger.debug("\t" + msg2)
            err, errstr = _rename_local_type(cur_tid, name)

            # handle temporary rename undoing failure
            if err:
                if logger.getEffectiveLevel() > logging.DEBUG:
                    logger.warning("failed " + msg2 + f": {errstr}")
                else:
                    logger.warning(f"\ttemporary rename undoing failed: {errstr}")

    return bool(err)


def parse_local_types(nhdr: str) -> Generator[tuple[str, str, str, str]]:
    # split according to empty lines
    decls = re.split(r"\n\n", nhdr)

    for decl in decls:
        decl = decl.strip()

        # extract the uuid of the type
        uuid_line, decl = decl.split("\n", maxsplit=1)
        r = parse.parse(LOCAL_TYPES_COMMENT_FMT, uuid_line)
        if not r:
            msg = f"failed to extract uuid from local type uuid line:\n{uuid_line}"
            raise LabSyncError(msg)
        decl_uuid = r.fixed[0]

        # extract the name of the type and generate a forward declaration for it
        name, decl_type = decl_to_name_and_type(decl)

        yield name, decl_uuid, decl, decl_type


def update_local_types(nhdr: str, types: netnode.Netnode) -> None:
    # parse type declaration names
    name2decl = {}
    uuids = {}
    decls = []
    fdecls = []
    typedefs = []
    for name, decl_uuid, decl, decl_type in parse_local_types(nhdr):
        # make sure it's unique, mostly for sanity purposes
        if name in name2decl:
            if (name2decl[name] == decl and
                uuids.get(decl_uuid) == name):
                # duplicate local type with same decl and UUID. probably accidentally copied from
                # both sides during conflict resolution. we'll skip the redundant copy
                continue

            msg = f"found two local type declarations with the same name: {name}"
            raise LabSyncError(msg)
        name2decl[name] = decl

        # remember the name for each uuid
        uuids[decl_uuid] = name

        # accumulate
        if decl_type in {"struct", "union", "enum", "class"}:
            decls.append(decl)

            fdecl = f"{decl_type} {name};"
            fdecls.append(fdecl)
        elif decl_type == "typedef":
            typedefs.append(decl)
        else:
            msg = f"found unexpected kind of local type:\n{decl}"
            raise LabSyncError(msg)

    # remove local types if required
    for tid, decl_uuid in list(types.items()):
        if decl_uuid not in uuids:
            name = ida_typeinf.get_tid_name(tid)
            logger.debug(f"removing local type {name!r}")
            ida_typeinf.del_named_type(None, name, ida_typeinf.NTF_TYPE)
            del types[tid]

    # rename local types if required
        # create a mapping from uuid to type name in our IDB
    cur_uuid_to_name = {u: ida_typeinf.get_tid_name(t) for t, u in types.items()}

    for decl_uuid, name in uuids.items():
        # skip if uuid doesn't exist (this is a new type) or name didn't change
        cur_name = cur_uuid_to_name.get(decl_uuid)
        if not cur_name or cur_name == name:
            continue

        # do the renaming
        rename_local_type(cur_name, name, types, uuids)

    # create a reordered header that that should be parsable with regards to forward declarations
    hdr = "\n".join(fdecls) + "\n\n" + "\n".join(typedefs) + "\n\n" + "\n\n".join(decls)

    # iteratively try to load the header as long as dependencies get resolved
    #
    # TODO @TH: originally we didn't move the typedefs to before the decls, so honestly I think
    #           that now there should always be just one iteration here. we should probably verify
    #           that and remove the loop here afterwards
    last_n_errors = float("inf")
    iters = 1
    while iters < len(name2decl) + 1:
        # parse some more local types
        n_errors = ida_typeinf.parse_decls(None, hdr, None, ida_typeinf.HTI_DCL)
        logger.debug(f"loaded local types with {n_errors} errors")

        # add new uuids. we do this on every iteration in case we will eventually bail out --
        # we don't want to have added new types without keeping their uuids
        for decl_uuid, name in uuids.items():
            tid = ida_typeinf.get_named_type_tid(name)
            if tid != ida_idaapi.BADADDR:
                if tid not in types:
                    types[tid] = decl_uuid
                else:
                    assert types[tid] == decl_uuid

        # stop if there are no more errors or if we didn't add anything on this iteration
        if n_errors == 0 or n_errors >= last_n_errors:
            break

        last_n_errors = n_errors
        iters += 1
    else:
        msg = "local type loading took more than it makes sense. aborting"
        raise LabSyncError(msg)

    logger.debug(
        f"finished loading local types with {n_errors} errors after {iters} iterations "
        f"({len(name2decl)} types)"  # noqa: COM812
    )

    if n_errors:
        # IDA SDK doesn't properly export an interface for printer_t so we can't get the actual
        # errors :/
        fd, hdr_path = tempfile.mkstemp(suffix=".h", text=True)
        os.write(fd, hdr.encode("latin1"))
        os.close(fd)

        logger.error(
            "run the following in IDC shell to see the local types parsing errors:\n"
            f'\tparse_decls("{hdr_path}", PT_FILE)'  # noqa: COM812
        )

        msg = f"failed to parse local types ({n_errors} errors)"
        raise LabSyncError(msg)

    # in case loading the local types resulted in a new type being created, we might've encountered
    # a bug where IDA recreates an anonymous local type for an unnamed embedded subtype
    #
    # in that case, look for and delete dangling anonymous local types that should've been left
    new_names = set(local_types())
    if set(name2decl.keys()) != new_names:
        for name in new_names:
            tinfo = ida_typeinf.tinfo_t()
            assert tinfo.get_named_type(None, name)

            # check if anonymous
            if not tinfo.is_anonymous_udt():
                continue

            # check if it has any xrefs
            tid = tinfo.get_tid()
            if (ida_xref.get_first_cref_to(tid) != ida_idaapi.BADADDR or
                ida_xref.get_first_dref_to(tid) != ida_idaapi.BADADDR):
                continue

            # check if it's referenced by any typedef
            used_by_typedef = False

            any_tinfo = ida_typeinf.tinfo_t()
            for any_name in local_types():
                assert any_tinfo.get_named_type(None, any_name)

                if not any_tinfo.is_typedef():
                    continue

                if any_tinfo.get_next_type_name() != name:
                    continue

                used_by_typedef = True
                break

            if used_by_typedef:
                continue

            # remove it
            logger.debug(f"removing dangling local type {name!r}")
            ida_typeinf.del_named_type(None, name, ida_typeinf.NTF_TYPE)
            del types[tid]


def update_prototypes(
    binary: SyncedBinary, storage: functioninliner.ClonesStorage, d: dict[int, str]) -> None:

    # delete prototypes if required
    #
    # dump_prototypes() is a bit heavy, so we duplicate some code here instead of calling it
    # because we don't need the actual prototypes
    for ea in idautils.Functions():
        seg = ida_segment.getseg(ea)
        seg_name = ida_segment.get_segm_name(seg)

        # skip funcs that are in inlined chunks somehow (shouldn't happen)
        if seg_name.startswith("inlined_"):
            continue

        # skip funcs that have been inlined
        if ea in storage:
            continue

        # delete type if untyped in the new dict
        dea = binary.ea2dump(ea)
        if dea not in d:
            logger.debug(f"removing prototype from {ea:#x}")
            ida_nalt.del_tinfo(ea)

    # update prototypes
    for dea, ptype in d.items():
        ea = binary.dump2ea(dea)
        cur_ptype = prototype(ea)

        # TODO @TH: because we had numerous issues with prototypes syncing, we want to make sure
        #           that we always apply all prototypes so that issues will be raised early.
        #           we can probably undo it after we feel more confident
        # if cur_ptype != ptype:
        if True:
            msg = f"changing {ea:#x} prototype from:\n\t{cur_ptype!r}\nto\n\t{ptype!r}"
            if cur_ptype != ptype:
                logger.debug(msg)

            success = ida_typeinf.apply_cdecl(
                None, ea, ptype + ";", ida_typeinf.TINFO_DEFINITE,
            )

            if not success:
                if logger.getEffectiveLevel() > logging.DEBUG or cur_ptype == ptype:
                    logger.warning("failed " + msg)
                else:
                    logger.warning("prototype change failed!")


def migrate(d: dict, types: netnode.Netnode) -> dict:
    ver = d["version"]
    if ver not in {1, 2, 3, 4}:
        msg = f"data file is of unexpected version: {ver}"
        raise LabSyncError(msg)

    # version 4 is latest
    if ver == 4:
        return d

    # version 3 was missing local type uuids
    fake_hdr = "\n\n" + d["local_types"]
        # turn the format string to a regex pattern
    cmt_pat = "^" + LOCAL_TYPES_COMMENT_FMT.format(r"[0-9a-f-]+").replace("*", r"\*") + "$"
    fake_hdr = re.sub(cmt_pat, "", fake_hdr, flags=re.MULTILINE)

    types_clone = dict(types.items())
    nhdr = normalize_local_types(fake_hdr, types_clone, split_pat="\n\n")
    d["local_types"] = nhdr

    if ver == 3:
        return d

    # version 2 was missing prototypes
    d["prototypes"] = dump_prototypes()

    if ver == 2:
        return d

    # version 1 was missing local types
    d["local_types"] = dump_local_types()

    return d


def parse_data(data: str, types: netnode.Netnode) -> dict:
    d = yaml.load(data, Loader=yaml.CLoader)  # noqa: S506
    return migrate(d, types)


def update(binary: SyncedBinary, data: str, types: netnode.Netnode) -> None:
    storage = functioninliner.ClonesStorage()
    storage.update_from_storage()

    d = parse_data(data, types)

    update_names(binary, storage, d["names"])
    update_inlined_funcs(binary, storage, d["inlined_funcs"])
    update_local_types(d["local_types"], types)
    update_prototypes(binary, storage, d["prototypes"])


def adopt_uuids(data: str, types: netnode.Netnode) -> None:
    # extract local types normalized header
    d = parse_data(data, types)
    nhdr = d["local_types"]

    # parse uuids
    name_to_uuid = {}
    for name, decl_uuid, _, _ in parse_local_types(nhdr):
        if name in name_to_uuid:
            msg = (
                f"found two local type declarations with the same name: {name} (uuids "
                f"{name_to_uuid[name]} and {decl_uuid})"
            )
            raise LabSyncError(msg)

        name_to_uuid[name] = decl_uuid

    # adopt uuids for local types we don't already have uuids for, if their names match
    for name in local_types():
        tid = ida_typeinf.get_named_type_tid(name)
        if tid == ida_idaapi.BADADDR:
            msg = f"failed to resolve tid of local type {name!r}"
            raise LabSyncError(msg)

        # skip local types that already have a uuid
        if tid in types:
            continue

        # adopt the uuid from the repo if it has a local type with the same name (best effort
        # heuristic)
        if name in name_to_uuid:
            decl_uuid = name_to_uuid[name]
            logger.debug(f"adopting repo uuid for local type {name!r}: {decl_uuid}")
            types[tid] = decl_uuid


# REPO


class LabSyncRepo:
    _path: str
    _repo: git.Repo

    def __init__(self, path: str):
        # TODO @TH: we should add a mechanism to lock the repo while we're doing git operations on
        #           it, in case multiple IDBs are using it at the same time

        self._path = path
        self._repo = git.Repo(path)

        with self._repo.config_reader() as cr:
            try:
                mergetool = cr.get("merge", "tool")
                logger.info(f"using merge.tool = {mergetool}")
            except (configparser.NoOptionError, configparser.NoSectionError):
                msg = "merge.tool must be set in git configuration to use this plugin"
                raise LabSyncError(msg)  # noqa: B904

        if self._repo.active_branch.name != "master":
            logger.warning("data repo is not on branch 'master'")

        with self._repo.config_writer() as cw:
            cw.set_value("mergetool", "keepbackup", "false")
            cw.set_value("mergetool", "writetotemp", "true")
            cw.set_value("mergetool", "hideresolved", "true")

    def _is_clean(self) -> bool:
        return not (self._repo.is_dirty() or self._repo.untracked_files)

    def _ensure_clean(self) -> None:
        if self._repo.is_dirty():
            msg = "data repo is dirty. please fix this externally for now"
            raise LabSyncError(msg)

        if self._repo.untracked_files:
            msg = "data repo has untracked files. please fix this externally for now"
            raise LabSyncError(msg)

    @property
    def path(self) -> str:
        return self._path

    def _pull(self) -> None:
        assert self._is_clean()

        # resolve remote tracking branch
        current = self._repo.active_branch
        tracking_branch = current.tracking_branch()
        if not tracking_branch:
            logger.warning("no remote tracking branch. skipping pull")
            return

        # pull
        try:
            self._repo.git.pull(rebase="false", allow_unrelated_histories=True)
        except git.GitCommandError as e:
            if "fix conflicts and then commit" not in e.stdout:
                raise

            logger.warning(f"pull failed with: {e.stdout}")
        else:
            return

        # resolve conflicts
        try:
            self._repo.git.mergetool("--no-prompt", "--gui")
        except git.GitCommandError as e:
            msg = (
                "mergetool returned failure. please fix the conflict and conclude the merge "
                "manually"
            )
            raise LabSyncError(msg) from e

        # conclude the merge
        self._repo.git.commit("--no-edit")

        # make sure that we're done
        if self._repo.is_dirty():
            msg = (
                "data repo is still dirty after supposedly committing the fixed merge. please "
                "fix the repo manually"
            )
            raise LabSyncError(msg)

    def _id_path(self, _id: str) -> pathlib.Path:
        return pathlib.Path(self.path) / f"{_id}.yaml"

    @contextlib.contextmanager
    def _open(self, _id: str, mode: str) -> IO:
        path = self._id_path(_id)
        with path.open(mode) as fp:
            yield fp

    def _commit(self, _id: str) -> None:
        index = self._repo.index
        index.add([_id + ".yaml"])
        # this is broken for some reason: index.commit(f"updated {_id}")
        self._repo.git.commit("-m", f"updated {_id}")

    def _commit_dangling(self, _id: str) -> None:
        index = self._repo.index
        index.add([_id + ".yaml"])
        index.commit(f"initial commit for {_id}", [])

    def _push(self) -> None:
        assert self._is_clean()

        # resolve remote tracking branch
        current = self._repo.active_branch
        tracking_branch = current.tracking_branch()
        if not tracking_branch:
            logger.warning("no remote tracking branch. skipping push")
            return

        # push
        self._repo.git.push()

    def get(self, _id: str) -> tuple[Optional[str], str]:
        self._ensure_clean()

        self._pull()

        commit = self._repo.commit().hexsha

        if self._id_path(_id).exists():
            with self._open(_id, "rt") as fp:
                data = fp.read()
        else:
            data = None

        return data, commit

    def put(self, _id: str, content: str, *, base: Optional[str]) -> tuple[str, bool]:
        self._ensure_clean()

        if base and self._repo.head.commit.hexsha != base:
            # we need to fetch before resetting, because if the IDB was copied from somewhere,
            # it could be that we don't locally have the base commit
            logger.debug("fetching repo")
            self._repo.git.fetch()

            logger.debug(f"resetting HEAD to {base}")
            self._repo.head.reset(base, working_tree=True)

        with self._open(_id, "wt") as fp:
            fp.write(content)

        if self._is_clean():
            logger.debug("no changes")

            changed = False
        else:
            if base:
                self._commit(_id)
            else:
                logger.debug("committing to a danging commit")
                self._commit_dangling(_id)

            changed = True

        return self._repo.commit().hexsha, changed

    def sync(self) -> str:
        self._pull()
        self._push()

        return self._repo.commit().hexsha

    def ping(self) -> bool:
        try:
            self._repo.git.ls_remote(heads=True)
        except git.GitCommandError:
            return False
        else:
            return True


# PLUGIN STUFF


class LabSyncActionBase(ida_kernwin.action_handler_t):
    plugin: ida_idaapi.plugin_t

    def __init__(self, plugin: ida_idaapi.plugin_t):
        super().__init__()
        self.plugin = plugin

    @property
    def name(self) -> str:
        return f"{self.plugin.wanted_name}:{self.__class__.__name__}"

    @property
    def label(self) -> str:
        raise NotImplementedError

    @property
    def shortcut(self) -> Optional[str]:
        return None

    @property
    def tooltip(self) -> Optional[str]:
        return None

    @property
    def icon(self) -> int:
        return 0

    @property
    def flags(self) -> int:
        return 0

    @property
    def path(self) -> str:
        return f"Edit/Plugins/{self.plugin.wanted_name}/"

    def register(self) -> None:
        desc = ida_kernwin.action_desc_t(
            self.name,
            self.label,
            self,
            self.shortcut,
            self.tooltip,
            self.icon,
        )
        ida_kernwin.register_action(desc)

    def unregister(self) -> None:
        ida_kernwin.unregister_action(self.name)

    def activate(self, ctx: Any) -> None:
        raise NotImplementedError

    def update(self, ctx: Any) -> None:
        raise NotImplementedError


class LabSyncEnableAction(LabSyncActionBase):
    @property
    def label(self) -> str:
        return "Enable"

    def activate(self, ctx: Any) -> None:
        self.plugin.enable()

    def update(self, ctx: Any) -> None:
        if self.plugin.enabled:
            return ida_kernwin.AST_DISABLE
        else:
            return ida_kernwin.AST_ENABLE


class LabSyncDisableAction(LabSyncActionBase):
    @property
    def label(self) -> str:
        return "Disable"

    def activate(self, ctx: Any) -> None:
        self.plugin.disable()

    def update(self, ctx: Any) -> None:
        if self.plugin.enabled:
            return ida_kernwin.AST_ENABLE
        else:
            return ida_kernwin.AST_DISABLE


class LabSyncResetAction(LabSyncActionBase):
    @property
    def label(self) -> str:
        return "Reset"

    def activate(self, ctx: Any) -> None:
        self.plugin.reset()

    def update(self, ctx: Any) -> None:
        if self.plugin.enabled:
            return ida_kernwin.AST_DISABLE
        else:
            return ida_kernwin.AST_ENABLE


class LabSyncHooks(ida_kernwin.UI_Hooks):
    plugin: ida_idaapi.plugin_t
    menu_actions: list[LabSyncActionBase]

    def __init__(self, plugin: ida_idaapi.plugin_t, menu_actions: list[LabSyncActionBase]):
        super().__init__()

        self.plugin = plugin
        self.menu_actions = menu_actions

    def ready_to_run(self) -> None:
        for action in self.menu_actions:
            ida_kernwin.attach_action_to_menu(
                action.path, action.name, ida_kernwin.SETMENU_APP,
            )

    def saved(self) -> None:
        if not self.plugin.enabled:
            return

        if self.plugin.sync_in_progress:
            return

        # TODO @TH: we need to figure out a way not to have this run on "Save as...".
        #           or if we do want it to run -- get_path(PATH_TYPE_IDB) here will still hold the
        #           "old" path so reinvoke the 2nd save differently
        changed = self.plugin.sync()
        if changed:
            logger.debug("resaving the idb with synced changes")
            idb_name = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
            # TODO @TH: can we somehow find the flags the original save was invoked with and reuse
            #           them?
            ida_loader.save_database(idb_name, 0)


class LabSyncPlugin(ida_idaapi.plugin_t):
    version: int = ida_idp.IDP_INTERFACE_VERSION
    flags: int = ida_idaapi.PLUGIN_MOD | ida_idaapi.PLUGIN_HIDE

    comment: str = "helps to partially synchronize IDBs over git"
    help: str = ""
    wanted_name: str = "LabSync"
    wanted_hotkey: str = ""

    menu_actions_types: list[type[LabSyncActionBase], ...] = \
        (LabSyncEnableAction, LabSyncDisableAction, LabSyncResetAction)

    CFGFILE: str = "labsync.cfg"
    NETNODE: str = "$ labsync.plugin"
    TYPES_NETNODE: str = "$ labsync.types"
    BINARIES_NETNODE: str = "$ labsync.binaries"

    COMMIT_KEY_PREFIX = "commit."

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.menu_actions = []
        self.hooks = None

        self._sync_in_progress = False

    @classmethod
    @property
    @functools.cache
    def netnode(cls) -> netnode.Netnode:
        """this netnode holds:
            commit.<idb_id>: Optional[str]  # the git commit this binary is synced to
            enabled: bool  # whether LabSync is enabled
            custom_idb_id: Optional[str]  # override of the IDB id to use
        """
        return netnode.Netnode(LabSyncPlugin.NETNODE)

    @classmethod
    @functools.cache
    def types(cls, idb_id: str) -> netnode.Netnode:
        """this netnode matches:
                tid [int]  # of a local type
            to
                uuid [str]  # of it in the YAML
        """
        name = f"{LabSyncPlugin.TYPES_NETNODE}.{idb_id}"
        return netnode.Netnode(name)

    @classmethod
    @property
    @functools.cache
    def _binaries_netnode(cls) -> netnode.Netnode:
        """this netnode matches:
                seg_prefix [str]  # prefix of segment names
            to
                tuple[str, int]  # of (<idb id>, <base ea>) to use for mapping segments to separate
                                 # YAMLs
        """
        return netnode.Netnode(LabSyncPlugin.BINARIES_NETNODE)

    @classmethod
    @property
    @functools.cache
    def cfg(cls) -> dict:
        path = (
            pathlib.Path(ida_diskio.get_user_idadir()) / ida_diskio.CFG_SUBDIR /
            LabSyncPlugin.CFGFILE
        )
        try:
            cfg_raw = path.open("rt").read()
        except OSError as e:
            logger.error(f"failed to read configuration file from {path!r}: {e}")  # noqa: TRY400
            return None

        cfg_parser = configparser.ConfigParser()
        try:
            cfg_parser.read_string("[section]\n" + cfg_raw)
        except Exception:
            logger.exception("failed to parse configuration file")
            return None

        return dict(cfg_parser["section"].items())

    @classmethod
    @property
    @functools.cache
    def repo(cls) -> LabSyncRepo:
        # validate/apply basic configuration
        if "repo_path" not in cls.cfg:
            logger.error("repo_path not found in configuration file")
            return None

        try:
            repo = LabSyncRepo(cls.cfg["repo_path"])
        except Exception:
            logger.exception("configured repo_path does not point to a valid git repo")
            return None

        logger.info(f"using repo: {repo.path}")

        return repo

    @classmethod
    @property
    def idb_id(cls) -> str:
        default_id = ida_nalt.retrieve_input_file_md5().hex()
        return cls.netnode.get("custom_idb_id", default_id)

    @classmethod
    def commit_key(cls, idb_id: str) -> str:
        return f"{cls.COMMIT_KEY_PREFIX}{idb_id}"

    def _register(self) -> None:
        for t in LabSyncPlugin.menu_actions_types:
            a = t(self)
            a.register()
            self.menu_actions.append(a)

        self.hooks = LabSyncHooks(self, self.menu_actions)
        self.hooks.hook()

    def _deregister(self) -> None:
        if self.hooks:
            self.hooks.unhook()

        for a in self.menu_actions:
            a.unregister()

    @staticmethod
    def is_compatible() -> bool:
        info = ida_idaapi.get_inf_structure()
        return info.procname == "ARM" and info.is_64bit()

    @staticmethod
    def _init_logging() -> None:
        logger_formatter = logging.Formatter(
            fmt="{name}.{levelname:<5s}: {message}", style="{",
        )

        logger_hdlr = logging.StreamHandler()
        logger_hdlr.setFormatter(logger_formatter)

        logger.addHandler(logger_hdlr)

        # may be overridden with the 'log' config entry
        logger.setLevel(logging.INFO)

    def migrate(self) -> None:
        # migrate types to be per binary
        old_types = netnode.Netnode(LabSyncPlugin.TYPES_NETNODE)
        new_types = self.types(self.idb_id)
        for tid, _uuid in list(old_types.items()):
            new_types[tid] = _uuid
            del old_types[tid]

        # migrate commit to be per binary
        old_commit = self.netnode.get("commit")
        if old_commit is not None:
            self.netnode[self.commit_key(self.idb_id)] = old_commit
            del self.netnode["commit"]

    def init(self) -> int:
        LabSyncPlugin._init_logging()

        if not self.cfg or not self.repo:
            return ida_idaapi.PLUGIN_SKIP

        for binary in self.binaries:
            if binary.seg_prefix is None:
                name = "main"
            else:
                name = f"{binary.seg_prefix}*"
            logger.info(f"{name} idb id: {binary.idb_id}")

        if self.enabled:
            logger.info("syncing enabled")
        else:
            logger.info("syncing disabled")

        self.migrate()

        for binary in self.binaries:
            commit = self.netnode.get(self.commit_key(binary.idb_id))
            if self.enabled or commit:
                logger.info(
                    f"{binary.idb_id} last synced to commit: {commit}",
                )

        log_level = self.cfg.get("log")
        if log_level:
            logger.setLevel(log_level)

        self._register()

        logger.info("initialized successfully")

        return ida_idaapi.PLUGIN_KEEP

    def term(self) -> None:
        self._deregister()

    def run(self, arg: int = 0) -> None:
        pass

    @classmethod
    @property
    def _lockfile_path(cls) -> pathlib.Path:
        return pathlib.Path(__file__).parent / LOCKFILE

    @contextlib.contextmanager
    def _lock(
        self, wait_timeout: Optional[float] = None,
    ) -> contextlib.AbstractContextManager[None]:
        """it makes more sense to logically lock the LabSyncRepo and not LabSyncPlugin, but it's
        problematic because we want to use a lockfile which orignally wasn't in the .gitignore of
        that repo (and so syncing older IDBs will fail because we'll create the lockfile and that
        will make the repo dirty)
        """

        deadline = time.monotonic() + wait_timeout
        while True:  # we want to try once even if the timeout is 0
            logger.debug("taking lock on the repo")
            try:
                fd = os.open(self._lockfile_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                pass

            if time.monotonic() >= deadline:
                logger.error(
                    "failed to get lock on the data repository within the configured timeout. "
                    "either another IDA instance is still syncing, or something bad happened "
                    "during a previous sync. if you're sure it's safe, you can delete the "
                    f"lockfile manually: {self._lockfile_path}"  # noqa: COM812
                )
                msg = "failed to get repo lock"
                raise LabSyncLockError(msg)

        try:
            yield
        finally:
            logger.debug("releasing lock on the repo")
            os.close(fd)
            self._lockfile_path.unlink()

    @property
    def sync_in_progress(self) -> bool:
        return self._sync_in_progress

    @classmethod
    @property
    def binaries(cls) -> tuple[SyncedBinary, ...]:
        rules = dict(cls._binaries_netnode.items())
        return cls._binaries_from_mapping_rules(rules)

    @classmethod
    def _binaries_from_mapping_rules(
        cls, rules: dict[str, tuple[str, Optional[int]]]) -> tuple[SyncedBinary, ...]:

        if not rules:
            return (SyncedBinary(idb_id=cls.idb_id),)

        # generate a synced binary per every segment matching rule and the default
        seg2bin = {}
        for seg_prefix, (idb_id, base_ea) in rules.items():
            # start with start_ea/end_ea pointing at max/min, and we'll have update them in the
            # next loop
            seg2bin[seg_prefix] = SyncedBinary(
                idb_id=idb_id, start_ea=ida_idaapi.BADADDR, end_ea=0, base_ea=base_ea,
                seg_prefix=seg_prefix,
            )
        default_bin = SyncedBinary(
            idb_id=cls.idb_id, start_ea=ida_idaapi.BADADDR, end_ea=0, seg_prefix=None,
        )

        # find the start/end EAs for each synced binary
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            name = ida_segment.get_segm_name(seg)

            # skip inlined chunks segments
            if name.startswith("inlined_"):
                continue

            matched = False
            for seg_prefix, binary in seg2bin.items():
                if name.startswith(seg_prefix):
                    binary.start_ea = min(binary.start_ea, seg.start_ea)
                    binary.end_ea = max(binary.end_ea, seg.end_ea)
                    matched = True

            if not matched:
                default_bin.start_ea = min(default_bin.start_ea, seg.start_ea)
                default_bin.end_ea = max(default_bin.end_ea, seg.end_ea)

        # remove synced binaries that didn't match any segment
        for seg, _bin in list(seg2bin.items()):
            if _bin.start_ea == ida_idaapi.BADADDR:
                del seg2bin[seg]
        if default_bin.start_ea == ida_idaapi.BADADDR:
            assert default_bin.end_ea == 0
            default_bin.start_ea = 0  # make it empty

        # make sure that none of the synced binaries overlap
        last_bin = None
        last_seg = None
        for _bin, seg in sorted(
                [(_bin, seg) for (seg, _bin) in seg2bin.items()] + [(default_bin, "<default>")],
            ):

            assert _bin.start_ea <= _bin.end_ea
            if last_bin:
                assert last_bin.start_ea <= _bin.start_ea
                if last_bin.end_ea > _bin.start_ea:
                    msg = f"Found overlapping segments for {last_seg!r} and {seg!r}"
                    raise LabSyncBinaryMatchingError(msg)

            last_bin = _bin
            last_seg = seg

        # validate/set base_ea-s
        for seg, _bin in seg2bin.items():
            if _bin.base_ea is None:
                _bin.base_ea = _bin.start_ea
            elif _bin.base_ea > _bin.start_ea:
                msg = f"Base EA for {seg!r} is greater than its start EA"
                raise LabSyncBinaryMatchingError(msg)

        binaries = (default_bin, *seg2bin.values())

        # make sure the we don't have overlapping IDB ids
        assert len(binaries) == len({b.idb_id for b in binaries})

        return binaries

    @classmethod
    def map_segments_to_idb_id(
        cls, seg_prefix: str, idb_id: str, *, base_ea: Optional[int] = None) -> None:

        rules = dict(cls._binaries_netnode.items())

        new_rules = rules.copy()
        seg_rule = (idb_id, base_ea)
        new_rules[seg_prefix] = seg_rule

        # check that the new rules are valid
        try:
            cls._binaries_from_mapping_rules(new_rules)
        except LabSyncBinaryMatchingError:
            logger.exception(f"failed mapping segment prefix {seg_prefix!r} to idb id {idb_id}")
            return

        # add the rule to netnode
        cls._binaries_netnode[seg_prefix] = seg_rule

        # invalidate previous types if we had them (since they might be outdated)
        types = cls.types(idb_id)
        for tid in list(types.keys()):
            del types[tid]

    def sync(self) -> None:
        assert not self.sync_in_progress

        try:
            self._sync_in_progress = True

            logger.debug("checking that the remote repository is reachable")
            if not self.repo.ping():
                logger.warning("skipping sync because the remote repository is unreachable")
                return False

            timeout = float(self.cfg.get("lock_timeout_sec", DEFAULT_LOCK_TIMEOUT))
            with self._lock(timeout):
                binaries = self.binaries
                for binary in self.binaries:
                    if len(binaries) > 1:
                        logger.debug(f"syncing {binary.idb_id}")

                    # in case this is the initial commit, try to adopt local types from the repo
                    # (in case this IDB was already synced)
                    base = self.netnode.get(self.commit_key(binary.idb_id))
                    if not base:
                        latest_data, latest_commit = self.repo.get(binary.idb_id)
                        if latest_data:
                            logger.debug(f"adopting local type uuids from commit: {latest_commit}")
                            adopt_uuids(latest_data, self.types(binary.idb_id))

                    # sync IDB -> repo
                    logger.debug("saving changes to repo")

                    data = dump(binary, self.types(binary.idb_id))
                    commit, changed = self.repo.put(binary.idb_id, data, base=base)

                    if changed:
                        # save the IDB with the updated types and commit, in case something will
                        # break later during the merge
                        #
                        # TODO @TH: this path will be wrong if we're under "Save as..." flow.
                        #           see comments under LabSyncHooks.saved
                        self.netnode[self.commit_key(binary.idb_id)] = commit

                        idb_name = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
                        ida_loader.save_database(idb_name, 0)

                    # sync repo with upstream
                    self.repo.sync()

                    # sync repo -> IDB
                    new_data, new_commit = self.repo.get(binary.idb_id)

                        # if there's a new commit with new data for our IDB -- update
                    if new_data != data:
                        logger.debug("updating with changes from repo")
                        with wait_box("updating with changes from repo...", hide_cancel=True):
                            update(binary, new_data, self.types(binary.idb_id))
                            changed = True

                        # save the commit we're synced to in netnode (even if just the commit
                        # changed)
                    if new_commit != commit:
                        self.netnode[self.commit_key(binary.idb_id)] = new_commit
                        changed = True

                    p = "" if len(binaries) == 1 else f"{binary.idb_id} "
                    s = "" if changed else " (no changes)"
                    logger.info(f"{p}synced to commit: {new_commit}{s}")

                return changed
        except BaseException as exc:  # noqa: BLE001
            ida_kernwin.warning("LabSync synchronization failed. See output window for more "
                                "details")
            if not isinstance(exc, LabSyncLockError):
                raise
        finally:
            self._sync_in_progress = False

    @classmethod
    def enable(cls) -> None:
        cls.netnode["enabled"] = True
        logger.info("syncing enabled")

        for binary in cls.binaries:
            commit = cls.netnode.get(cls.commit_key(binary.idb_id))
            logger.info(
                f"{binary.idb_id} last synced to commit: {commit}",
            )

    @classmethod
    def disable(cls) -> None:
        cls.netnode["enabled"] = False
        logger.info("syncing disabled")

    @classmethod
    def reset(cls) -> None:
        # make sure that we're already disabled, to make sure that no one resets by mistake
        assert not cls.enabled

        idb_ids = {}

        # delete the commit states
        for k in cls.netnode.keys():  # noqa: SIM118
            if k.startswith(cls.COMMIT_KEY_PREFIX):
                idb_ids.add(k[len(cls.COMMIT_KEY_PREFIX):])
                del cls.netnode[k]

        for binary in cls.binaries:
            idb_ids.add(binary.idb_id)

        # delete the tid->uuid mapping for all of the IDB ids we noted
        for idb_id in idb_ids:
            types = cls.types(idb_id)
            for tid in list(types.keys()):
                del types[tid]

        logger.info("sync data reset")

    @classmethod
    @property
    def enabled(cls) -> bool:
        return cls.netnode.get("enabled", False)


def PLUGIN_ENTRY() -> ida_idaapi.plugin_t:  # noqa: N802
    return LabSyncPlugin()
