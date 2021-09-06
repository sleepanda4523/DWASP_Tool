from download_read import MakeDataset
from CVSS_graph import Cvss
from cvss_freq import final
from vuln_Freq import freq
import numpy as np
import pandas as pd
from cwe import Database
import time


class main(MakeDataset, Cvss, freq, final):
    def get_name(self, path):
        try:
            num = self.df.iloc[path, 1].split('-')[1]
            if num == 'CWE':
                num = 0
            week = self.db.get(int(num))
            if week is None:
                self.cwe_name[path] = 'Nop'
            else:
                self.cwe_name[path] = week.name
        except:
            print(f'err {path}')

    def set_dataset(self):
        df = pd.read_excel(self.savedir + 'dataset.xlsx')
        self.df['CVE-ID'] = df['id']
        self.df['CWE-ID'] = df['cwe']
        self.df['CVSS'] = df['cvss']

        print('Get CWE Data..')
        self.cwe_name = ['' for i in range(self.df.shape[0])]
        for i in range(0, self.df.shape[0]):
            self.get_name(i)
        self.df['CWE-NAME'] = self.cwe_name
        print('Got CWE Data')


def run():
    main_class = main()
    time.sleep(1)
    sy, ey = map(int,input("Year Input(Start year End year): ").split())
    main_class.clean_dataset(sy, ey)
    main_class.set_dataset()
    main_class.make_graph(sy, ey)
    main_class.make_freq()
    main_class.make_final()


if __name__ == "__main__":
    run()
