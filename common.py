#!/usr/bin/env python3
import os

# function that returns if the user is root or not
def has_root():
    return os.geteuid() == 0
