import docopt
import logging
import warnings
import traceback
from processor import AttackDetector
warnings.filterwarnings("ignore")

__doc__ = """ddetect to detect Ddos detector

Usage:
    ddetect --help
    ddetect -i inputfile -o outputfile -n threshold

Options:
    -v <verbosity> --verbosity=<verbosity>
    -i <inputfile> --input=<inputfile>
    -o <outputfile> --output=<outputfile>
    -n <threshold> --num=<threshold>
"""


def main():
    args = docopt.docopt(__doc__)
    try:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(levelname)-8s %(message)s',
                            datefmt='%a, %d %b %Y %H:%M:%S',
                            filename='ddos.log',
                            filemode='w')

        attack_detector = AttackDetector(logging)
        input_file = args['--input']
        output_file = args['--output']
        threshold = args['--num']
        record_list = attack_detector.load_input(input_file)

        '''
        sends the data onto the main function for detecting the suspicious IP
        '''
        set_of_suspicious_ips = attack_detector.fraud_detection(
            record_list,
            threshold)
        attack_detector.write_output(set_of_suspicious_ips, output_file)
        # Displays the suspicious IP count on the console
        logging.info("Suspicious IPs : {}".format(len(set_of_suspicious_ips)))
    except Exception, e:
        logging.error(traceback.print_exc())
        logging.error(e)


if __name__ == "__main__":
    main()