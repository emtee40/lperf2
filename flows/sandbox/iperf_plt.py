#!/usr/bin/python3

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from matplotlib.pyplot import MultipleLocator
from queue import Queue
import random, threading, time
from signal import signal, SIGINT, SIGTERM, SIGKILL
import sys
import subprocess as sbp
import re
import os

# subprocess of shell process
subp_obj = None

####################################
# SIGINT handler
def handler(signal_received, frame):
    global subp_obj
    print('SIGINT or CTRL-C detected. Exiting gracefully')
    subp_obj.terminate()
    subp_obj.wait()
    os.killpg(subp_obj.pid, SIGTERM)
    sys.exit()

# Tell Python to run the handler() function when SIGINT is recieved
signal(SIGINT, handler)

#############################################
# producer class
class Producer(threading.Thread):
    def __init__(self, name, queue, sbp_shl):
        threading.Thread.__init__(self, name=name)
        self.data = queue
        self.shl = sbp_shl

    def run(self):
        '''
        child = sbp.Popen(['./speed.sh','-c'],stdout=sbp.PIPE,stderr=sbp.STDOUT)
		child.daemon = True # open daemon process
        '''

        '''
        for i in range(1000):
            tmp = random.uniform(10,15)
            self.data.put(tmp)
            print("%s put %f to queue！" %(self.getName(), tmp))
            time.sleep(0.5)
		'''

        while True:
            out = self.shl.stdout.readline()
            if self.shl.poll() is not None:
                break
            else:
                self.data.put(out)


####################################
# figure and axis setting
plt.rcParams["figure.figsize"] = [10, 5]
plt.rcParams["figure.autolayout"] = True
fig,ax = plt.subplots(dpi=100)

'''
# x axis interval
x_major_locator = MultipleLocator(1)
ax.xaxis.set_major_locator(x_major_locator)
'''

# line
xdata, ydata = [], []
ln, = ax.plot([], [], color='cornflowerblue', lw=1, label="Speed(Mbits/sec)")

ax.set_title("Bandwidth")
ax.set_xlabel('Time')
ax.set_ylabel('Speed(Mbits/sec)')
ax.legend()
ax.grid(alpha=0.4)

# key press handler
def key_press(event):
    global subp_obj
    if event.key == 'q':
        print('press q to exit all figures')
        subp_obj.terminate()
        subp_obj.wait()
        os.killpg(subp_obj.pid, SIGTERM)
        sys.exit()
fig.canvas.mpl_connect('key_press_event', key_press)

####################################
# FuncAnimation
# update line
def update(frame):
	if frame != None:
		#print(frame)
		ydata.append(frame)
		xdata = range(0, len(ydata))

		ax.set_xlim(0, max(xdata)+1)
		ax.set_ylim(0, int(max(ydata)*1.2))
		ln.set_data(xdata, ydata)
		fig.canvas.draw_idle()
		fig.canvas.flush_events()
		fig.tight_layout()
		return ln,

# init line
def init():
	return ln,

# frame callback function
def gen_frame():
	while True:
		if queue.empty():
			yield(None)
		else:
			out = queue.get(block=False)
			out_str = out.strip().decode()
			res = re.findall('Mbits/sec', out_str)
			if(res != []):
				print(out_str)
				data = out_str.split()
				pos = data.index('Mbits/sec')
				spd = float(data[pos-1])
				yield(spd)
			else:
				yield(None)

# animation
ani = FuncAnimation(fig, update, frames=gen_frame, init_func=init, interval=200, repeat=False)

####################################
# subprocess start
subp_obj = sbp.Popen(['./speed.sh','-c'],stdout=sbp.PIPE,stderr=sbp.STDOUT,preexec_fn=os.setsid)

# thread start
queue = Queue()  # class queue object
producer = Producer("Producer", queue, subp_obj)  # class Producer object 
producer.daemon = True # open daemon process
producer.start()  # start class object

# plot show
plt.ion()
plt.show(block=True)
