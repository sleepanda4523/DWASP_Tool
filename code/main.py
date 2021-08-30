from download_read import MakeDataset
from CVSS_graph import Cvss
import time


class main(MakeDataset, Cvss):
    pass


def run():
    main_class = main()
    time.sleep(1)
    sy, ey = map(int,input("Year Input(Start year End year): ").split())
    main_class.clean_dataset(sy, ey)
    main_class.set_dataset()
    main_class.make_graph(sy, ey)



if __name__ == "__main__":
    run()
