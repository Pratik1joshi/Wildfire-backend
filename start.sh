#!/bin/bash
uvicorn prediction_api:app --host=0.0.0.0 --port=8000
