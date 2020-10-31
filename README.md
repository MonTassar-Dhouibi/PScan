# Foobar

PScan is a little python script excitable in any compiler and terminale, builded with python 2.7 by Montassar dhouibi. 

## Installation

Use the package manager [git] 

```
git clone https://github.com/Monta-sys/PScan
```

## Usage

```python                                 PScan  [ARG] [TARGET SITE]  [ATTACK] --[OPTION]             ATTACK:                                                             -a --adminFinder  :select panel finder attack               -p --PortScan     : select Ports Scanner attack     ARGUMENTS:                                                          -v --victimHost   : give the url adress of the target host                                                      OPTION:                                                             -t --Time_Out     :give the value of timeout in secends
        -i --interval     :give the interval of ports begin and end to try "exemple:
 PScan -p -v www.targetHost.com -i 23 84 "

Exemple:  PScan -p -v www.hostname.com -t 0.5

           credit by MonTassar_Dhouibi
        uploaded in www.github.com/Monta-sys/PScan

```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
