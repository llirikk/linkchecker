import linkchecker
from utils import Map

if __name__ == '__main__':
    options = Map({'configfile': './developrc', 'url': ['https://www.example.com']})
    linkchecker.main(options)