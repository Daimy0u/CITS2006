import os
import json

from src.base import Base

current_directory = os.getcwd()
files = os.listdir(current_directory)

BASE = current_directory + '/rules' + '/base/base.yar'
CONFIG = json.load(current_directory + '/config.json')

        
class YaraEngine:
    def __init__(self):
        self.base = Base(BASE)
        self.queue = []
        self.