class HitStructure:
    def __init__(self, time_stamp, count):
        self._time_stamp = time_stamp
        self._count = count

    @property
    def time_stamp(self):
        return self._time_stamp

    @property
    def count(self):
        return self._count

    @time_stamp.setter
    def time_stamp(self, time_stamp):
        self._time_stamp = time_stamp

    @count.setter
    def count(self, count):
        self._count = count
