from datetime import datetime
import os
import sys


class HitStructure:
    def __init__(self, timeStamp, count):
        self.timeStamp = timeStamp
        self.count = count

    def gettimeStamp(self):
        return self.timeStamp

    def getCount(self):
        return self.count

    def settimeStamp(self, timeStamp):
        self.timeStamp = timeStamp

    def setCount(self, count):
        self.count = count


class Record(object):
    
    def __init__(self, ipAddress, timeStamp):
        self.ipAddress = ipAddress
        self.timeStamp = timeStamp

    def getIpAddress(self):
        return self.ipAddress

    def gettimeStamp(self):
        return self.timeStamp

    def setIpAddress(self, ipAddress):
        self.ipAddress = ipAddress

    def settimStamp(self, timeStamp):
        self.timeStamp = timeStamp


class AttackDetector(object):

    def calculateTimeDifference(self, lastHitTime, currentTime):
        difference = 0
        try:
            desiredFormatForDifference = '%H:%M:%S'
            difference = datetime.strptime(currentTime, desiredFormatForDifference) - datetime.strptime(lastHitTime,
                                                                                                        desiredFormatForDifference)
            difference = difference.seconds * 1000
        except TypeError, e:
            raise e
        return difference

    def loadInput(self, inputFile):
        recordList = []
        try:
            dataFile = open(inputFile, 'r')
            # recordList = []
            for line in dataFile:
                # sends each line of the file to the split function in order to populate the Record data structure from the required fields of the record in the actual file
                record = self.splitFields(line)
                recordList.append(record)
            dataFile.close()
        except IOError, e:
            raise e
        return recordList

    def fraudDetection(self, recordList, threshold):

        mapOfRecords = {}  # responsible for maintaining the count of seen IP's in the current 2minute window
        suspiciousIPs = set()  # responsible for mainitaining the suspicious IPs

        """
            1.If IP not in map, add a new entry into the map with the following data:
                Key : IP
                Value : Hit Structure [timestamp:timestampOfTheIP,count:1]
            2.If IP in map,check whether the timestamp is within the last 30 secs
                a.If yes, increment the count value in the Hit Structure by 1
                b.If no, update the entry in the map with the timestamp of this IP and resetting the count to 1.
            3.If the count exceeds the threshold, add it to the set of suspicious IPs

        """

        for record in recordList:
            ipAddress = record.getIpAddress()
            currentTime = record.gettimeStamp()
            # Implements step 2. of the above algorithm
            if ipAddress in mapOfRecords:
                lastHitTime = mapOfRecords[
                    ipAddress].gettimeStamp()  # fetches the last timestamp this IP was seen in the 2 minute window
                difference = self.calculateTimeDifference(lastHitTime,
                                                          currentTime)  # calculates the difference between current record and last seen same IP record
                # print("Difference :"+ str(difference))
                diffSeconds = int(difference / 1000 % 60)
                diffMinutes = int(difference / (60 * 1000) % 60)
                diffHours = int(difference / (60 * 60 * 1000))
                # Implements step 2a. of the above algortihm
                if diffHours == 0 and diffMinutes == 0 and diffSeconds <= 30:
                    updateCount = mapOfRecords[ipAddress].getCount();
                    h = HitStructure(lastHitTime, updateCount + 1)
                    mapOfRecords[ipAddress] = h
                    # Implements step 3 of the above algortihm
                    if updateCount + 1 >= threshold:
                        if ipAddress not in suspiciousIPs:
                            suspiciousIPs.add(ipAddress)
                # Implements step 2b. of the above algortihm
                else:
                    h = HitStructure(lastHitTime, 1)
            # Implements step 1 of the above algorithm
            else:
                h = HitStructure(currentTime, 1)
                mapOfRecords[ipAddress] = h
        return suspiciousIPs

    def writeOutput(self, suspiciousIPs, outputFile):
        outputFile = os.path.expanduser('~') + outputFile
        try:
            os.remove(outputFile)  # If the file already exists, remove it
        except OSError:
            pass
        fileHandler = open(outputFile, 'a')
        # Write the unique list of suspicious IP's onto a different file
        for ip in suspiciousIPs:
            fileHandler.write(ip + "\n")
        fileHandler.close()

    # Function to accept a line and populate the Record Data Structure for easy access
    def splitFields(self, line):
        fields = line.split(" ")
        timestamp = fields[3].split(":", 1)[1].split(" ", 1)[0]
        r = Record(fields[0], timestamp);
        return r


def main():
    try:
        attackDetector = AttackDetector()
        recordList = []
        inputFile = sys.argv[1]
        outputFile = sys.argv[2]
        threshold = int(sys.argv[3])
        recordList = attackDetector.loadInput(inputFile)
        # sends the data onto the main function for detecting the suspicious IP's
        setOfSuspiciousIPs = attackDetector.fraudDetection(recordList, threshold)
        attackDetector.writeOutput(setOfSuspiciousIPs, outputFile)
        # Displays the suspicious IP count on the console
        print("Suspicious IPs : " + str(len(setOfSuspiciousIPs)))
    except Exception, e:
        print(e)


if __name__ == "__main__":
    main()
