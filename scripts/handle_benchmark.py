import math
import sys
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import statistics
import csv
import shutil
from matplotlib.gridspec import GridSpec
from matplotlib.ticker   import MaxNLocator

####################################################################################

matplotlib.rcParams['axes.formatter.limits'] = (-5, 4)

MAX_LOCATOR_NUMBER = 10
FIGURE_XSIZE = 10
FIGURE_YSIZE = 8

BACKGROUND_RGB = '#F5F5F5'
MAJOR_GRID_RGB = '#919191'

LEGEND_FRAME_ALPHA = 0.95

####################################################################################

def set_axis_properties(axes):
    axes.xaxis.set_major_locator(MaxNLocator(MAX_LOCATOR_NUMBER))
    axes.minorticks_on()
    axes.grid(which='major', linewidth=2, color=MAJOR_GRID_RGB)
    axes.grid(which='minor', linestyle=':')

####################################################################################

class BenchmarkResult:
    def __init__(self, exec_time, data_size):
        self.exec_time = exec_time
        self.data_size = data_size

####################################################################################

def get_index_by_el(list, element):
    for index, value in enumerate(list):
        if value == element:
            return index

    return -1

def parse_csv(filename):
    encryption_regimes = set()
    data_sizes         = set()

    with open(filename, 'r') as file:
        csv_reader = csv.DictReader(file)
        for line in csv_reader:
            encryption_regimes.add(line['encryption_regime'])
            data_sizes.add(int(line['data_size']))

    encryption_regimes = sorted(list(encryption_regimes))
    data_sizes         = sorted(list(data_sizes))

    data_array = []
    for regime in range(len(encryption_regimes)):
        data_array.append([])

    with open(filename, 'r') as file:
        csv_reader = csv.DictReader(file)
        for line in csv_reader:
            regime = get_index_by_el(encryption_regimes, line['encryption_regime'])
            data_array[regime].append(BenchmarkResult(float(line['exec_time']), int(line['data_size'])))

    return data_array, data_sizes, encryption_regimes

def plot_matrix_res(data_array, data_sizes, encryption_regimes):
    figure = plt.figure(figsize=(FIGURE_XSIZE, FIGURE_YSIZE), facecolor=BACKGROUND_RGB)
    gs = GridSpec(ncols=1, nrows=1, figure=figure)
    axes = figure.add_subplot(gs[0, 0])
    set_axis_properties(axes)

    axes.set_xlabel('Size of user-data in bytes')
    axes.set_ylabel('Elapsed time')
    axes.set_title('Encryption time & size of user-data')

    for regime in range(len(encryption_regimes)):
        exec_time = [data_array[regime][i].exec_time
                        for i in range(len(data_array[regime]))]

        data_size = [data_array[regime][i].data_size
                        for i in range(len(data_array[regime]))]

        axes.plot(data_size, exec_time, "*-",
                  label=("encryption_regime: " + encryption_regimes[regime]))


    axes.set_yscale('log')
    axes.set_xscale('log')

    axes.legend()
    figure.tight_layout()

    plt.savefig('regimes.png')

####################################################################################

# SCRIPT START

if len(sys.argv) < 2:
    print("Invalid amount of arguments [at least 1 required]", file=sys.stderr)
    exit(1)

data_filename = sys.argv[1]
data_array, data_sizes, encryption_regimes = parse_csv(data_filename)
plot_matrix_res(data_array, data_sizes, encryption_regimes)
