from linkcheck.api import run
from linkcheck.utils import Map

if __name__ == '__main__':
    options = Map({'configfile': './developrc', 'url': ['https://www.example.com']})
    run(options)
