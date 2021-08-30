import numpy as np
import pandas as pd
from cwe import Database
import matplotlib.pyplot as plt


class Cvss:
    savedir = "../data/"
    cvss_df = pd.DataFrame()
    db = Database()
    resultdir = '../result/'

    def get_name(self, path):
        try:
            num = self.cvss_df.iloc[path, 1].split('-')[1]
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
        self.cvss_df['CVE-ID'] = df['id']
        self.cvss_df['CWE-ID'] = df['cwe']
        self.cvss_df['CVSS'] = df['cvss']

        print('Get CWE Data..')
        self.cwe_name = ['' for i in range(self.cvss_df.shape[0])]
        for i in range(0, self.cvss_df.shape[0]):
            self.get_name(i)
        self.cvss_df['CWE-NAME'] = self.cwe_name
        print('Got CWE Data')
        #self.cvss_df.to_excel(self.resultdir + 'test.xlsx', engine='xlsxwriter')

    def make_graph(self, sy, ey):
        print("Making CVSS graph..")
        cvss_list = self.cvss_df['CVSS']
        count = {'0': 0, '1': 0,
                 '2': 0, '3': 0,
                 '4': 0, '5': 0,
                 '6': 0, '7': 0,
                 '8': 0, '9': 0, }
        for i in range(0, len(cvss_list)):
            cnt = cvss_list[i]
            if cnt < 1:
                count['0'] += 1
            elif cnt < 2:
                count['1'] += 1
            elif cnt < 3:
                count['2'] += 1
            elif cnt < 4:
                count['3'] += 1
            elif cnt < 5:
                count['4'] += 1
            elif cnt < 6:
                count['5'] += 1
            elif cnt < 7:
                count['6'] += 1
            elif cnt < 8:
                count['7'] += 1
            elif cnt < 9:
                count['8'] += 1
            else:
                count['9'] += 1
        x = ['0-1', '1-2', '2-3', '3-4', '4-5',
             '5-6', '6-7', '7-8', '8-9', '9-10']
        y = np.array([int(count[str(i)]) for i in range(0, 10)])
        colors = ['#00c400', '#00e020', '#00f000', '#d1ff00', '#FFE000',
                  '#FFCC00', '#FFBC10', '#FF9C20', '#FF8000', '#FF0000']
        plt.figure(figsize=(20, 13))
        plt.bar(x, y, color=colors)
        plt.xticks(fontsize=20)
        plt.yticks(fontsize=20)

        for i, v in enumerate(x):
            plt.text(v, y[i], y[i],  # 좌표 (x축 = v, y축 = y[0]..y[1], 표시 = y[0]..y[1])
                     fontsize=20,
                     color='black',
                     horizontalalignment='center',  # horizontalalignment (left, center, right)
                     verticalalignment='bottom')  # verticalalignment (top, center, bottom)

        plt.title(f'CVSS Distribution for {sy}–{ey}', loc='center', pad=20, fontsize=30)
        plt.savefig(self.resultdir + 'CVSS Graph.png')
