# Defining the drain jobs and maintenance modes

**Status**: Proposed <!-- |Accepted|Rejected|Superceded|Deprecated -->

## Context

There are many scenarios when users would want to stop an AutoscalingRunnerSet from accepting new jobs, but still allow the current jobs to finish. Some examples:

- Putting the AutoscalingRunnerSet into maintenance mode.
- Decomissioning an AutoscalingRunnerSet.
- Migration of an AutoscalingRunnerSet to a new cluster.
- Solving the overprovisioning problem that happens when an AutoscalingRunnerSet is updated while it has pending or running jobs.

At the moment, the controller has no way of instructing the listener to change its behaviour during runtime. In this case, to pause resources updates or stop accepting new jobs while the running and pending jobs finish.

## Drain jobs mode

The drain jobs mode instructs the controllers manager, and the listener to wait until all running and pending jobs are finished before applying changes to the resources. This mode is useful when any of the existing resources are updated while there are pending or running jobs. It will prevent the creation of new resources, e.g. a new listener pod which will subsequently create new runner pods for jobs that are already assigned to the existing runner pods (the overprovisioning problem described earlier).

The new mode will be implemented in the following steps:

- Add a flag to the manager `drain-jobs-mode` which will be passed as an argument to the manager when it is started
- Add a new field `flags.drainJobsMode:` (enabled by default) to the gha-runner-scale-set-controller helm chart to allow users to disable the drain jobs mode

## Maintenance mode

- TBD
