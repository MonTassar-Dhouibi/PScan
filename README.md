## PScan

PScan is a little python script excitable in any compiler and terminale, builded with python 2.X AND 3.X by Montassar dhouibi. 


![img](https://github.com/Monta-sys/PScan/blob/master/src/img001.jpg)


## Installation

Use the package manager [git] 

```
$ git clone https://github.com/Monta-sys/PScan
$ cd PScan
$ pip install requirements.txt
$ python PScan.py

```

## Usage

``` 
$ ./PScan -[ARG] [TARGET SITE] -[ATTACK] --[OPTION]
```



``` python
ATTACK: 
          -a --adminFinder  :select panel finder attack               
          -p --PortScan     : select Ports Scanner attack 
    
ARGUMENTS:                                                          
          -v --victimHost   : give the url adress of the target host                                                      
OPTION:                                                             
          -t --Time_Out     :give the value of timeout in secends
          -i --interval     :give the interval of ports begin and end to try 

Exemple:  PScan -p -v www.hostname.com -t 0.5
          PScan -p -v www.targetHost.com -i 23 84 


           credit by MonTassar_Dhouibi
        uploaded in www.github.com/Monta-sys/PScan

```

## License
```
MIT License

Copyright (c) 2020 Montassar Dhouibi

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

```
[Licence](https://github.com/Monta-sys/PScan/blob/master/LICENSE) 

