import pcapy
import ConfigParser

class Reader(object):
    def __init__(self, in_file, outputs):
        self.p = pcapy.open_offline(in_file)
        self.o = list()

        for name, f in outputs:
            p = pcapy.compile(pcapy.DLT_EN10MB, 4096, f, 0, 1)
            o = self.p.dump_open(name)
            self.o.append((p, o))

    def callback(self, hdr, data):
        for p, o in self.o:
            if p.filter(data):
                o.dump(hdr, data)
                return

    def loop(self):
        self.p.loop(0, self.callback)

class Output(object):
    def __init__(self, name, f):
        self.name = name
        self.f = f

def main():
    c = ConfigParser.ConfigParser()
    c.read('config.ini')
    pcapfile = c.get('main', 'pcapfile')

    outputs = list()

    for output in c.get('filter_dumper', 'outputs').split(','):
        name = c.get(output, 'name')
        f = c.get(output, 'filter')
        outputs.append((name, f))

    r = Reader(pcapfile, outputs)
    r.loop()
    

if __name__ == '__main__':
    main()
