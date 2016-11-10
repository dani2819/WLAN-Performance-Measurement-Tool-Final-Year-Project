#!/usr/bin/env
import threading
import time
import Queue

def exampleJob(q):
    time.sleep(.5) # pretend to do some work.
    with print_lock:
        print(threading.current_thread().name,1)




# Create the queue and threader 
q = Queue.Queue()
print_lock = threading.Lock()

# how many threads are we going to allow for

t = threading.Thread(target=exampleJob,args=(q,))

     # classifying as a daemon, so they will die when the main dies
t.daemon = True

     # begins, must come after daemon definition
t.start()

start = time.time()



# wait until the thread terminates.
t.join()
print(q.get());
# with 10 workers and 20 tasks, with each task being .5 seconds, then the completed job
# is ~1 second using threading. Normally 20 tasks with .5 seconds each would take 10 seconds.
print('Entire job took:',time.time() - start)