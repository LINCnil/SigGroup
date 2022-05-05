FROM ubuntu 

RUN apt-get update \
  && apt-get install -y wget tar flex build-essential bison libgmp3-dev python3 python3-pip \
  && rm -rf /var/lib/apt/lists/*

RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && tar -xf pbc-0.5.14.tar.gz && cd /pbc-0.5.14 && ./configure && make && make install
COPY . /SigGroup/
RUN cd SigGroup/ && cp parameters.yaml.docker parameters.yaml && make && pip install -r requirements.txt && LD_LIBRARY_PATH=/usr/local/lib python3 initialisation.py
#RUN LD_LIBRARY_PATH=/usr/local/lib ./crypto

EXPOSE 9091 9092 9093
RUN apt-get clean 
CMD cd SigGroup/ && LD_LIBRARY_PATH=/usr/local/lib /SigGroup/launch.sh
