from workers.tasks import run_scan_task


def dispatch(job_id, path):

    run_scan_task.delay(job_id, path)