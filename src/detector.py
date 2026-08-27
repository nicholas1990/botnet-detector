"""Orchestrazione: cattura -> parsing -> statistiche -> scoring -> alert."""


class Detector:
    def run(self):
        raise NotImplementedError
