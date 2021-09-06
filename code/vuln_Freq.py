import numpy as np
import pandas as pd
from cwe import Database


class freq:
    savedir = "../data/"
    df = pd.DataFrame()
    db = Database()
    resultdir = '../result/'

    def plus_des(self, df):
        cwe_des = ['' for i in range(df.shape[0])]
        for i in range(0, df.shape[0]):
            num = df.iloc[i, 2].split('-')[1]
            if num == 'CWE':
                num = 0
            week = self.db.get(int(num))
            if week is None:
                cwe_des[i] = np.NaN
            else:
                cwe_des[i] = week.description
        df['CWE-DES'] = cwe_des
        #print(cwe_des)
        return df

    def make_freq(self):
        cwe_data = self.df.replace('Nop', np.NaN)['CWE-NAME'].value_counts(sort=True, dropna=True).reset_index(
            name='count')
        select_df = self.df.drop(['CVE-ID', 'CVSS'], axis=1)
        result_df = pd.merge(cwe_data.rename(columns={'index': 'CWE-NAME'}), select_df.drop_duplicates(['CWE-NAME']))
        result_df = self.plus_des(result_df)
        result_df.to_excel(self.resultdir + 'freq.xlsx', engine='xlsxwriter', index=False)
