"""
Module that has all classes used for request submission to computing
"""
import logging
import time
import traceback
from threading import Thread
from queue import Queue, Empty
from core_lib.utils.settings import Settings


class Worker(Thread):
    """
    A single worker thread that loops and submits requests from the queue
    """

    def __init__(self, name, task_queue):
        Thread.__init__(self)
        self.name = name
        self.queue = task_queue
        self.logger = logging.getLogger()
        self.logger.debug('Worker "%s" is being created', self.name)
        self.job_name = None
        self.job_start_time = None
        self.running = True
        self.start()

    def run(self):
        self.logger.debug('Worker "%s" is starting', self.name)
        while self.running:
            try:
                job_name, function, args, kwargs = self.queue.get(timeout=1)
                self.job_name = job_name
                self.job_start_time = time.time()
                self.logger.debug('Worker "%s" got a task "%s". Queue size %s',
                                  self.name,
                                  job_name,
                                  self.queue.qsize())
                try:
                    function(*args, **kwargs)
                except Exception as ex:
                    self.logger.error('Exception in "%s" during task "%s"',
                                      self.name,
                                      job_name)
                    self.logger.error(traceback.format_exc())
                    self.logger.error(ex)
                finally:
                    self.logger.debug('Worker "%s" has finished a task "%s". Queue size %s',
                                      self.name,
                                      job_name,
                                      self.queue.qsize())
                    self.job_name = None
                    self.job_start_time = 0
            except Empty:
                pass

    def join(self, timeout=None):
        self.running = False
        self.logger.debug('Joining the "%s" worker', self.name)
        Thread.join(self, timeout)


class WorkerPool:
    """
    Pool that contains all worker threads
    """

    def __init__(self, workers_count, task_queue):
        self.workers = []
        for i in range(workers_count):
            worker = Worker(f'worker-{i}', task_queue)
            self.workers.append(worker)

    def get_worker_status(self):
        """
        Return a dictionary where keys are worker names and values are dictionaries
        of job names and time in seconds that job has been running for (if any)
        """
        status = {}
        now = time.time()
        for worker in self.workers:
            job_time = int(now - worker.job_start_time if worker.job_name else 0)
            status[worker.name] = {'job_name': worker.job_name,
                                   'job_time': job_time}

        return status


class Submitter:
    """
    Request submitter has a reference to the whole worker pool as well as job queue
    """

    # A FIFO queue. maxsize is an integer that sets the upperbound
    # limit on the number of items that can be placed in the queue.
    # If maxsize is less than or equal to zero, the queue size is infinite.
    __task_queue = Queue(maxsize=0)
    # All worker threads
    __workers_count = 3
    __worker_pool = WorkerPool(workers_count=__workers_count,
                               task_queue=__task_queue)

    def __init__(self):
        self.logger = logging.getLogger()

    def add_task(self, name, function, *args, **kwargs):
        """
        Add a job to do to submission queue
        Name must be unique in the queue
        """
        for task in list(Submitter.__task_queue.queue):
            if task[0] == name:
                raise Exception(f'Task "{name}" is already in the queue')

        for worker, worker_info in Submitter.__worker_pool.get_worker_status().items():
            if worker_info['job_name'] == name:
                raise Exception(f'Task "{name}" is being worked on by "{worker}"')

        self.logger.info('Adding a task "%s". Queue size %s', name, self.get_queue_size())
        Submitter.__task_queue.put((name, function, args, kwargs))

    def get_queue_size(self):
        """
        Return size of submission queue
        """
        return self.__task_queue.qsize()

    def get_worker_status(self):
        """
        Return dictionary of all worker statuses
        """
        return self.__worker_pool.get_worker_status()

    def get_names_in_queue(self):
        """
        Return a list of task names that are waiting in the queue
        """
        return [x[0] for x in self.__task_queue.queue]

    def submit_job_dict(self, job_dict, connection):
        """
        Submit job dictionary to ReqMgr2
        """
        headers = {'Content-type': 'application/json',
                    'Accept': 'application/json'}

        try:
            # Submit job dictionary (ReqMgr2 JSON)
            reqmgr_response = connection.api('POST',
                                             '/reqmgr2/data/request',
                                             job_dict,
                                             headers)
            self.logger.info(reqmgr_response)
            workflow_name = json.loads(reqmgr_response).get('result', [])[0].get('request')
        except Exception:
            if reqmgr_response:
                reqmgr_response = str(reqmgr_response).replace('\\n', '\n')

            raise Exception(f'Error submitting {prepid} to ReqMgr2:\n{reqmgr_response}')

        return workflow_name

    def approve_workflow(self, workflow_name, connection):
        """
        Approve workflow in ReqMgr2
        """
        try:
            # Try to approve workflow (move to assignment-approved)
            # If it does not succeed, ignore failure
            approve_response = connection.api('PUT',
                                                f'/reqmgr2/data/request/{workflow_name}',
                                                {'RequestStatus': 'assignment-approved'},
                                                headers)
        except Exception as ex:
            self.logger.error('Error approving %s: %s', workflow_name, str(ex))
            return False

        return True
