# LabSync

LabSync is an IDA plugin that can be used to partially synchronize IDBs between different users
working on reversing the same binaries.

LabSync is intended to be non-intrusive, lightweight, and easy to use for very frequent syncs
(think as frequently and easily as you saved your IDB before Undo was a thing).

The leading use case is multiple people reversing the same binary at the same time, and especially
for binaries that don't start from a good "baseline" IDB (i.e. no typing information, non-standard
formats or architectures), and whose structure keeps changing during the reversing process.

## How it works

When enabled, whenever the IDB is saved, LabSync will synchronize some of its data with other
reverse engineers using a shared git repo.

LabSync generates a YAML from some of the data stored in your IDB (e.g. names, types, inlined
functions, etc.), and when you save the IDB this YAML is also committed to the shared git repo. The
repo is then pulled and pushed to sync with others.

In case there were any remote changes since the last time you saved your IDB, they will be fetched
during the git pull operation and merged into your local changes.

In case of any merge conflicts, git mergetool will automatically be started for you to resolve them
in a convenient textual format, and the sync process will finish afterwards.

The YAML for each IDB is saved under the MD5 of the input file, so LabSync is able to sync it with
other reverse engineers no matter their local IDB filename, as long as it originated from the same
binary.

## Example

We generated an example YAML for the `gzip-O3-moutline` example from the FunctionInliner repo
([source](https://github.com/cellebrite-labs/FunctionInliner/tree/master/test) /
[binary](example/gzip-O3-moutline)) after inlining all outlined
functions, and you can take a look at it [here](example/f396862963d4f7ec5f518b09bee77115.yaml).

An example of conflict resolution can be seen in the following animation (we change some function
name and sync, while it was also changed in upstream since our last change):

![](example/conflict.gif)

## Motivation

In Cellebrite Labs we often have multiple researchers working at the same time on reversing huge
binaries with no symbols or typing information. The structure of some of these also undergos
drastic changes during the reversing process (e.g. when
[FunctionInliner](https://github.com/cellebrite-labs/FunctionInliner) is used).

After reviewing past and existing IDA synchronization solutions, we failed to find a solution that
satisfied the following requirements:

1. Syncing should be very fast and non-intrusive -- either live or as quick and easy as a keypress.
2. In case of non-live synchronization or live-synchronization supporting offline work
   (i.e. where conflicts can occur), we want conflict resolution to be clear, intuitive and
   non-intrusive.
   1. Require the least amount of user interaction
   2. Be "easy" for a user unfamiliar with IDA/the solution internals
   3. Conflict resolution should not be a "must" when you just want to open the IDB to check
      something
3. [FunctionInliner](https://github.com/cellebrite-labs/FunctionInliner) should be a "first class
   citizen"
   1. IDA's [built-in outlined function support](https://hex-rays.com/blog/igors-tip-of-the-week-106-outlined-functions)
      (which is trivial to sync) is not sufficient for "deep" reversing, for example because xrefs
      from outlined chunks to functions/data are not propagated the "parent" functions, and because
      it makes static analysis of disassembly practically impossible.
   2. Non-live syncing of FunctionInliner's effects on the IDB are practically impossible without
      the solution being "FunctionInliner-aware" (i.e. because if two users inline different
      functions before syncing, the "clone" segments will most likely collide on the same unused
      EAs).

We tried to develop a solution based on the Pareto principle -- support the minimum amount of
features that will give the maximum amount of assistance to shared reversing work. We also
chose to dismiss syncing of features that, even if very helpful, would require a lot of
maintenance, or would require going down deep rabbit holes of edge cases. For example, we chose to
*not* sync decompiler comments, because we suspected that it will require exact-same decompilation
for all users which is impossible in the general case unless perfect synchronization is achieved
for a lot of other features).

We chose to use YAML files to store the data because they're easily editable by humans that will
need to understand what's going on and resolve potential conflicts.

We chose to use git as a backend because it's proven to work well for storing text files,
handling merges and conflicts and everyone already knows how to use it (or should :) ).

## Installing

1. Install the dependencies listed in `requirements.txt` where IDA can import them. For example
   using `/path/to/python3/used/by/ida -m pip install -r requirements.txt`.
2. Optionally install [FunctionInliner](https://github.com/cellebrite-labs/FunctionInliner).
3. Clone this repository and symlink `~/.idapro/plugins/labsync.py` to `labsync.py` in the cloned
   repo.
4. Create a new (empty) git repository that will be used for the synchronization data. This repo
   should be cloned by all of the users that will share their work.
5. Follow the next section on how to configure LabSync.

## Configuring

1. LabSync expects to find its configuration file under `~/.idapro/cfg/labsync.cfg`
2. Copy the example `labsync.cfg` from this repository and change `repo_path` to point to the path
   where your local clone of the *data* repository is (i.e. the one from step 4 above).
3. Make sure that you have `merge.tool` configured in your git configuration (either globally or
   locally for the *data* repo).
   1. You can check what it's globally configured to with `git config --global merge.tool`
   2. In case the above is empty, you should configure it e.g. with
      `git config --global merge.tool opendiff`
   3. You can test your configured `merge.tool` using
      [this repo](https://github.com/redguardtoo/test-git-mergetool).

## Usage

To start synchronizing the current IDB to LabSync, use `Edit > Plugins > LabSync > Enable`.

Afterwards -- just save your IDB regularly in order to synchronize to the repository.

NOTE: when resolving merge conflicts for names/prototypes, make sure that you verify the EAs of the
conflicting chunks you're comparing. Git's merge strategy compares the files line-by-line and
isn't aware of YAML's syntax, so it may create a conflict when two different adjacent keys have
been added to a dictionary such as `names` or `prototypes`.

## What does it sync?

We currently only sync:

1. Names given to EAs (e.g. functions, globals)
2. EAs of functions that have been inlined with functioninliner
3. Local types (i.e. structures, unions, enums)
4. Function prototypes

## Advanced features

### Branching out

You can checkout a different branch on the data repository and push it to the remote data
repository, and then your changes will sync only with people that are using the same branch,
and won't affect everyone else.

Unless you intend to merge back into the main branch eventually, it's recommended to keep a copy
of your IDB before you do the above so it'll be easy to revert once done.

### Local type tracking

LabSync generates a UUID for each local type and documents it in a comment above the local type
definition written in the YAML. This is used to track renames of local types, so that we don't
delete and re-create a local type in case it was renamed remotely (since then all references to it
will be destroyed).

When first enabling sync on an IDB whose binary has already been synced in the past, LabSync will
try to "adopt" the UUIDs saved in the repo for local types that have the same names as those saved
in the repo.

Note that this is a best-effort heuristical approach to reduce the amount of "duplicate" local
types that will then have to be replaced manually. However, this heuristic might not be complete,
and/or may also lead to false positives (e.g. a logically-different local type with the same name
as one saved in the repo will be assigned its UUID).

Please take the above into consideration when reviewing the initial commit merge, and replace
false-positive UUIDs with new random ones.

### Resetting synchronization

In order to reset the synchronization state of an IDB, you should first disable the synchronization
using `Edit > Plugins > LabSync > Disable` and then use `Edit > Plugins > LabSync > Reset`.

If LabSync will be enabled afterwards, it'll treat the IDB as "new" when syncing it with the repo,
and in case it won't be deleted from git, it'll be merged with the existing repo data.

### Mapping segments to a different data file

In some cases it's useful to reverse a binary together with a software library that it uses in the
same IDB. In order to support syncing features related to the library between the IDBs of different
binaries that use it, you can ask LabSync to sync some segments to separate files.

Note that all of the local types will be synced to all of the associated files, so in case of a
conflict involving local types, you may have to resolve it more than once during conflict
resolution.

This functionality is mostly intended to be used by IDA loaders, so we don't expose it using UI,
but rather using the following API:

```python
from labsync import LabSyncPlugin
LabSyncPlugin.map_segments_to_idb_id(seg_prefix, idb_id)
```

Where `seg_prefix` is e.g. `libwhatever.` and `idb_id` can technically be any string, but is
expected to be the MD5 hash of the `libwhatever` binary. This will cause LabSync to sync features
(e.g. names, prototypes) related to EAs whose segment name starts with `<seg_prefix>` to
`<idb_id>.yaml` instead of the main YAML file.

Because the library may be loaded to different EAs in different IDBs, the EAs in the library
YAML will be relative to the start EA of the first matching segment. If needed, you can override
the base EA by providing a `base_ea` argument to `map_segments_to_idb_id`.

## Known issues

1. LabSync does not currently do things as creating functions or changing their properties, so this
   may lead to issues e.g. when syncing inlined functions that don't have the same function end.

   Therefore we recommend to start using LabSync on a certain IDB only after it has passed the
   basic preprocessing it has to go through, in case there is any (e.g. inlining all outlined
   functions, on applicable IDBs).

2. When testing LabSync with IDBs created from binaries that had some type information, we found
   that there are multiple kinds of issues with local types and prototypes autogenerated by IDA,
   where if you just try to reapply the same local type or prototype that are already there it will
   already fail.

   We tried to solve some of them, e.g. by adding forward declarations of pointed types that were
   used in function prototypes, but some were more problematic to solve and you will have to solve
   them manually.

   Some kinds of the issues we don't currently resolve:
   1. IDA sometimes has issues reapplying prototypes which use namespaced types (e.g. try repplying
      the type for the `_copy` function in the `gzip-O3-moutline` example that we used [above](
      #example)). In such cases it's best it's best to tick `Don't display this message again` when
      the `Bad declaration. See the message window for details.` popup shows and ignore it.
   2. Syncing of templated types, e.g. from stl (currently we skip dumping them to the YAML and
      spit a warning instead).
   3. In some cases IDA generates
      [VFT structs](https://docs.hex-rays.com/user-guide/user-interface/menu-bar/view/c++-type-details)
      with the `_vtbl_layout` suffix instead of `_vtbl`.
      On reimport, IDA will yell that constructors/destructors must have the name of the class
      (even though it allows a `_vtbl` suffix). You can rename these structs and change the
      `_vtbl_layout` suffix to `_vtbl` in order to work around the issue.
   4. We encountered cases where IDA would complain about `Type 'id' is already defined` where
      some struct name is `id` under namespaces. You can rename it to work around the issue.
   5. We encountered an issue where IDA misinterprets nested namespaces, e.g. for:
      ```c
      struct B::fields {
        int b;
      };

      struct A {
        B::fields b;
      };
      ```
      It complains that `B::A::fields` does not exist. This is problematic with the naming scheme
      used by `ida_kernelcache`. We're currently investigating a workaround for this issue.

## Troubleshooting

- Q: I finished resolving a conflict with the mergetool, but IDA still hangs!
- A: In case you're using macOS, you have to actually quit the mergetool application for git/IDA
     to see that it's "done".

<!-- -->

- Q: Something went wrong during conflict resolution and I just want to go back!
- A: Go to your data repository and do `git merge --abort`

<!-- -->

- Q: I have a merge conflict on the UUID comment that LabSync added. What should I do?
- A: First read the part about *Local type tracking* above to understand what these UUIDs mean.
     Essentially, what happened is that both you and upstream have added a type with the same
     name. If these types are logically different, abort the merge (as explained in the previous
     answer), rename your local structure and resync. If these types are logically same, you
     should do the same (rename and resync) and then replace all of the usages one of them to the
     other, delete the one that is now unused, and resync. On older IDA versions there was an
     [automated way to do it](https://hex-rays.com/blog/igors-tip-of-the-week-142-mapping-local-types),
     but at least on IDA 8.4 it seems to be gone.

## Future work

1. Auto-resolving of YAML conflicts -- a lot of git conflicts can be resolved by a YAML-aware merger
   (e.g. when two adjacent functions are renamed, git will conflict but there is no logical
   conflict)
2. Sync "data" types -- currently we only sync types for function EAs (i.e. prototypes) and not for
   "data" EAs
3. Merging names of functions and their prototypes into one in the YAML (currently a logical
   conflict in a function name change will result in two git conflicts)
4. Synchronizing different segments to different files (useful for situations where libraries are
   sideloaded to different binaries)
5. "git blame" tooltip -- see who last named/typed a function to ask them about it
6. YAML metadata -- add a title/description of the IDB to the YAML

## Meta

Authored by Tomer Harpaz of Cellebrite Labs
Developed and tested for IDA 8.4 on macOS with Python 3.9.19
