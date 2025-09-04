#!/bin/bash

# while inotifywait -e close_write src/*.js
while inotifywait -e close_write *.py 
do
    echo Running make at $(date)
    make
done
