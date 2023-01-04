import os
import sys
import struct
from ctypes import *
from ecdsa import SigningKey, NIST384p
from hashlib import sha384
import argparse
import base64
import zlib
import pickle
import json

PGSIZE = 0x1000

ACPI = b'eJzt3Ad0VGXf7v9JCBCGFiCA9NCbQCY9UiSFEkhCSEIHQwi9hi4iUlQEREWKHQwI9oK9K/aGiopdFBV7Q2zY4Ow9szP3xTXXft/zPrPOOeuslfn/TzLJns8vmfned5L3XvisitrWLSLCY99WbO0yxOOp59kYPWnxjNmLZsxduHVjrUnLFk0pXbCgdNnWLVszPTEeT2FRdlxBcWHczyMLi0dk5EZ6rE928PsY/9v9nqpb1a3qVnWrulXdqm5Vt6pb1a3qVnWrulXdqm7/v9+2Xri1cOsQz9E2nunVMp3/m//U2+E2/9e/qapb1a3qVnWrulXdqm5Vt6pb1a3qVnWrulXdqm7/Z2/OgUBMTOWBwMCMrILYCI+nxuzAPxHIy8kqHFY0sNj+VwZ5zvvKW4Sn1v/2F4qK9ERFWe+neL6pFvhMXeuTHs/9F8Z4IqI9EYlRlTM9kbENAicTDznvI+KsR0aFzoyI8URGic+f8hjLRkeZ+3X+m8fjLW/h4GXlUxaMtF6Tov7/xeMi/5s5wwbkxU+2v36t//41/U9v2UXZxR8cjvBE1rUnjsyzP473+V9PT05+cW6t6s3ixq3KzBlW5Kljn/94T45bnVvd/jgib1BCZpz1JjducF5Opv0mN25QVob/zeC4gqz84rj8kdkZcUVZAwdFF9tvCuw3g+03+fabTPtN0aDRA6ILMrIHWJ/LL46JLimKL2loVfdY95ID9yoabLWR/Zkk+zMRnnFrhsb0LCnKLBmZNyw7umRwTnZda/3lxMfHJ1mPGpGTbb3NKixqkB/lHXJRU4+nTjX13Dd0d7uibss8G+yZXm9eTn5K4G69vIzRzt0muQPyUy7z3+1iPSA1cDfeeoBzt7/1gNTY7OolOfk5nnL7tbPn2Hdybeq/M3GB/bklE+2xy+wX1Rtbar/P9cZOKi+1x5ZPsseUT/I/MtX/yNSYdvYr4Y+UGeHt4o0etzrGvl8tMyO7MC4zO6M4btyaPr2qVb5eGQU5Wf7XrE7GAU+1wAvVytt8bS07+uET9m4O3N/nv7/MU5FRa6sd0XrZM6P8L/uIjEJf5YjqEdEl2dn5dbOG5fkCL35EYGYTb6NBEcerHa8WEb2+hqdaROBFHLcmKzgjQcxICMzwRuKQyOORzpBqzpD+0eYJjczLLIouKs4o8daPLrGesycwzPr0iCJPYHVY9xcvdJZGbIOS7Jwiz3K/qGu/tT5TUBTvWRGY4f9M7RLrnWe3fT/aupjoLKha3hrt4zwR9ncwpKv5DooL8hIqv7T/y1mfiPfF269HlvWhvbWcDwMvj/3t5c0oWzBv4bypi+JGzliwaHHp7DgLxSX0jLfXeXFhg1RvUp5nhqfMs8Azz7PQ+n9TPYs8cZ6R1ucWWPcWe0o9s62Piz0FnjzrfYKnpyfe43G+zwbeeoGGB52GsbUCT8hbf9yqQTnDSiJq94/xrxT7g2pZxbkFcdZCKYiLHdawuKAgxxtdMHRQQmAfWvcSG1a3X/hd/RtY33xxSbyn/OrpHvtORb0t/o93N6jujTwZsTO/XkVd/2cidtf19Uz07MyrW1Hb/wlv5G5vtZ35dSq6Bj6sVu71f9lyzzr7S3k85fbX99+P8Oy23+3M8FbaqN3eyJ2ZtSr6Bj6sXu6t7reVJDHCU+6tceqnvJGewOxEj39e4s6M6pXzatjfS2ZURevAhzXLvTX9+Px1M6wfidaE3fabnXGVD4gu90aLB+zZHRE7OKo4LyvHu6sfvzJ1Kl8Za9HubFPRKvCylHt99rYMDLL35m77jT1oSFRJdlFeHetLTm/QyBtz41+H+rZIuS9/d4dLYqK3NynabWeZOavy8g/FE1Mb7V88cFPLQSPfPXZwwm77u5g5y/5qnoqsmlvtH6vWIs2p4d9rAwqySgJ7rePBenUC68vn7TnAM9daX7OtlbTE+gUbZ62kUs80/70s616ZZ7r/vu+UlVXX6116MnA7ZVWtGRjt/1KDBuRnBVb9yLySQVPmlmTNWzx30ZQFzs7w/2YsGYlXSkb6gj+0A/v2FBfbIyPb3li5VkP/giy3f8mssz8M3B/sv28tGvtdTLOSQQUDYhuVDIiP96wdH/yWvKvGrUnxf1RYnBVf+XOn9im/Lfw/a8qtVeOJ9P+sifb/rKnIrLvV/v3kGbfKepdn/Rrc99aJ2p6Ycasb2x9nFRTmZMcNKyr22W8SrB+1WfCjyXqEz3k1nE1esGBe2ZSFC+ctiMuYNm3BlGmli6y72VOWzCib4jnlN1mWJ7ZtScEI65lbbwK/9srtr7XO/tDeIta72KYl1hetXeHdMsNTPtP++uUz7G8lprX/VTjNehUyrVfh1O/Hu6oio8vWTP8P9FWZGcX2UzrqPKWu9sdZmVbUOOvNgLjMQuu3R2ZWRkGc9V0VxWXmF1kf5mflWk8zs6kZaylfdGbO6JKG+TViPZ7a6xpZ/3+E/e7XCO9fdezFUjums/994IOvq3kne60b/BT0r4weI4M/DTNLF1n5l3kqX7ngHXPFY3/NAQ3TrS9pZkf43zqfcfmqnsD/d2qZyrGBCgX5BfFZ8Rme2BYl1hfxWD/W7FfF22a3/TR31rDfDYgdWL3E+qz1bRQVlzT0/7loPedy+5VbZ3/KWp/2C+i/b9WzX0f/fetHU0WTwLz65f5vLfDpap7d9vvKXz72A6xfPlm5DWtE+H/Fr+lfHX6NZ/lKTlkwifR8MrLiMiaXlgf2npliTS8oKvTstoPGDK7pXygZNa2Vkm59h1bficsnRpQun+iNnGT9qJ7kjcTlY3f2rsbP2N+Fd9XObhVdtpRGhDx0VehDyyfa66diTY2orfmBvykGpPr3pfW3YuG4Vfkjc4ZZ6/GAsx4T7Y+zCq0fjHFZ/je5RTn2m8K4/AEj4+03PvtNgv0m0X6TFGfPyM702H96+kc0tD/sb/0tMHDViZp5mQNz4/BV8yX4f91aIcZF5OcVj/bEDqnt/zm8K88b+Ilu/0TdfoXzQ31QLf+Pcfsn8O6vYnpdvuNIg/VvNey95Y/xj+waWtMPfNavgBn2o30VGTXsR/sidg2u7r+UYF2aaV9KCPx2SPDstp/azrRx7e2vffKk9WthlvW3vfW9ls+0r0QXWncbVLe/63L7s/aH4zrbj91t391jrUP729uzx/8uNr+e9SINrLsro5741ofWCX7rx54bOGrXLZMz76h35NBLh3es2jXMy9/6gFrOt54b7fat20F25taIzsnPHt2gmjdqXCP7nscbM9B6H/jAG+ONybbulM+0P1c+274vnqv90Kz/+dPNjrZWQ16t4MDp9upwn7HBvuvJHpUd77/njbLu+gJ3o627CfYfOjmBP3TK7UfZfzvkBO77/Pcj/PcT/PetLWz/UZETO6i2tRrzaluvQkFxg6ja/9S3n3lBsccbl1k8bGDgA2+cN654YG5x+XT7c+Uz7PvB79p+QKC4va7h219qv/FGT3R9GosmeuNKxzXyP4O40tzM3Gz7KRQ2rBnpsV+f4JMotJ6EfdV/P/DHVWHFoOqbt0bY/yfXuDW5UYFNau/AfOsHSeAvWet3qJUkys48cPqMmbPsT8bWL7FeYus3rfW6+z9uYH1cGGl97BwIxAUPBArzps+wH1Ix2PpC3kj5lXz+rxTxP/tKwcE59uBqgcF5pw4O/DHujQxncpScnBiYXC2cydXl5KTA5KhwJteQk5MDk6uHM7mmnJwSmFwjnMnRcnJqYHLNcCbXkpPTApOjw5nslZPTA5NrhTO5tprsC2xJrzecyXXk5MAW9NYOZ3JdOdnZg3XCmVxPTnb2YN1wJteXk509WC+cyTFysrMH64czuYGc7OzBmHAmN5STnT3YIJzJjeRkZw82DGdyrJzs7MFG4UxurCYnOHswNpzJTeRkZw82DmdyUznZ2YNNwpl8mpzs7MGm4UxuJic7e/C0cCY3l5OdPdgsnMkt5GRnDzYPZ3JLOdnZgy3CmdxKTnb2YMtwJreWk5092CqcyW3U5ERnD7YOZ3KcnOzswTbhTG4rJzt7MC6cye3kZGcPtg1ncns52dmD7cKZ3EFOdvZg+3Amd5STnT3YIZzJneRkZw92DGdyZznZ2YOdwpncRU529mDncCZ3VZOTnD3YJZzJ3eRkZw92DWdydznZ2YPdwpl8upzs7MHu4UzuISc7e/D0cCb3lJOdPdgjnMm95GRnD/a0JjsHAvHBA4H/+EvFyy/lbMpe4TwJn5zsbMr4cCYnyMnOpvSFMzlRTU52NmVCOJOT5GRnUyaGMzlZTnY2ZVI4k1PkZGdTJoczOVVOdjZlSjiT0+RkZ1OmhjM5XU52NmVaOJPPkJOdPZgezuTecrKzB88IZ3IfOdnZg73DmdxXTU5x9mCfcCb3k5OdPdg3nMlnysnOHuwXzuT+crKzB88MZ3KGnOzswf7hTM6Uk509mBHO5Cw52dmDmeFMzpaTnT2YFc7kAXKyswezw5k8UE529uCAcCYPUpNTnT04MJzJg+VkZw8OCmdyjpzs7MHB4UweIic7ezAnnMlD5WRnDw4JZ3KunOzswaHhTM6Tk509mBvO5Hw52dmDeeFMHiYnO3swP5zJBXKysweHhTN5uJqc5uzBgnAmF8rJzh4cHs7kIjnZ2YOF4UwulpOdPVgUzuQRcrKzB4vDmTxSTnb24IhwJo+Sk509ODKcyaPlZGcPjgpn8hg52dmDo8OZPFZOdvbgmHAmj1OT0509ODacyePlZGcPjvsfT3YOBPoHDwTgS02QX8rZlOPDeRJnycnOppwQzuQSOdnZlGeFM3minOxsypJwJpfKyc6mnBjO5ElysrMpS8OZXCYnO5tyUjiTJ8vJzqYsC2fyFDHZ5/zDGu/kcCZPlZOdTTklnMnT5GRnD04NZ/J0OdnZg9PCmTxDTnb24PRwJs+Uk509OCOcybPkZGcPzgxn8mw52dmDs8KZPEdOdvbg7HAmz5WTnT04J5zJ89Tkyn9JMzecyeVysrMH54Uzeb6c7OzB8nAmL5CTnT04P5zJC+VkZw8uCGfyIjnZ2YMLw5m8WE529uCicCYvkZOdPbg4nMlL5WRnDy4JZ/LZcrKzB5eGM3mZmlz5L2nODmfyOXKysweXhTN5uZzs7MFzwpl8rpzs7MHl4UxeISc7e/DccCafJyc7e3BFOJNXysnOHjwvnMmr5GRnD678zybHZJ/w/5cSef+WDIjP8JSPh9kDRsZPpE/4SukTCZPoE4ll9ImkyRX5fTZvmeipaL55y/KJEZ7gf7jj/PPSeO/qihb2JW9kyDVf8FpUyLWE4LXokGuJwWsxIdeSgtfiQq4lB6/1D7mWEry2KuRaqnWtpX2ttif0CaaZi6HPMN1cDHmKvnhzMeQ5+nzmYsiT9CWYiyHP0pdoLoY8TV+SuRjyPH3269Pavlgn8J9S0+UUuBwZejkVLkeFXk6Dy9Ghl9PhckzI5YR4uBwXetkHl/uHXk6Ay6tCLyfC5dDCCUl42TkQKAgeCIRET8CXMTR7Ar6MoeET8GUMTZ+AL2No/AR8GUPzJ+LLGLoAEq2XsXwi/ZDw7+/SwP4uDXlxEiv3aWno/k5MDF4LeRUSk4LXQl6CxOTgtZDnn5gSvBby5BNTg9dCn3la8Fro067cpaVifyfFm4shzzDJZy6GPMWkBHMx5DkmJZqLIU8yKclcDHmWScnmYsjTTEoxF0OeZ1Ll0iqV+zspDS6H7u+kdLgcur+T4+Fy6P5O9sHl0P2dnACXQ/d3ciJcDt3fyUlwOXR/JyfD5dDCySl4OaRxMr5qoZWT8VUL7ZyMr1po6RR81UJbp+CrFlo7BV+10N4p1qtWXkq/4v3beVJgO08KeS1SKrflpNDtnJIcvBbyKqSkBK+FvAQpqcFroc8/LXgt9MmnB6+FPPPU+OC1kKedWrkpJ4ntnJpgLoY8w9REczHkKaYmmYshzzE12VwMeZKpKeZiyLNMTTUXQ59mmrkY+jwrl9YkuZ3T4uFy6HZO88Hl0O2clgCXQ7dzWiJcDt3OaUlwOXQ7pyXD5dDtnJYCl0O3c1oqXA4tnJaGl0Map+GrFlo5HV+10M7p+KqFlk7HVy20dTq+aqG10/FVC+2dbr1q5ZPoD3T/di4LbOeykNcivXJbloVu5/TU4LXQVyEteC30JUgPXuPn7wv+tV8Wsp19wb/2y0K2sy/4135ZyHb2xVduyrLQ7eyLTzIX+Rn64pPNRX6KvvgUc5Gfoy/4F39Z6Hb2Bf/iLwvdzr7gX/xlodvZF/yLvyx0O/t8lUurTG1nny8BLodsZ58vES6HbGefLwkuh2xnX/Av/zK1nX3Bv/zL1Hb2Bf/yL1Pb2Rf8y79MbWdf8C//MrWdfcG//MvUdvYl4KsWWjkBX7XQzgn4qoWWTsBXLbR1Ar5qobUT8FUL7W3/oV9edup2TqzIjtq8ZbKnorHFJvtfi+D/yoB3VUUT+7OBnWw+vbp88qlDkip6bt4aUeA/TehQ4P/vleF/byHV+Z/zMf8jKBXx9n/qHHh8xwL/f4Yc+nhvJIFqBiRKUI1AlAFJEkQRqG5AsgTVCdQwIEWCGgRqGpAqQU0C0QakSRBNoJYB6RLUIuANAl+8BF4CtQ2Qob21CdQxQJeuQ6CuAbp0XQL1DNCl6xGob4AuXZ9AjAG6dAyBBgbo0g0INDRAl25YCZwDgYnBAwFnQiMzQadvRF8yNggSdPpYAo0N0OkbE2higE7fhEBTA3T6pgROM0CnP41AMwN0+mYEmhug0zcn0MIAnb4FgZYG6PQtCbQyQJduRaB1ECTq0q0JtDFAl25DIM4AXTqOQFsDdOm2BNoZoEu3I9DeAF26PYEOBujSHQh0NECX7kigkwG6dCcCnQ3QpTsT6BIESbp0FwJdDdCluxLoZoAu3Y1AdwN06e4ETjdAlz6dQA8DdOkeBHoaoEv3JNDLAF26F4F4A3TpeAI+A3RpH4GEIEjWpRMIJBqgSycSSDJAl04ikGyALp1MIMUAXTqFQKoBunQqgTQDdOk0AukG6NLpBM4wQJc+g0BvA3Tp3gT6BEGKLt2HQF8DdOm+BPoZoEv3I3CmAbr0mQT6G6BL9yeQYYAunUEg0wBdOpNAlgG6dBaBbAN06WwCAwzQpQcQGBgEqbr0QAKDDNClBxEYbIAuPZhAjgG6dA6BIQbo0kMIDDVAlx5KINcAXTqXQJ4BunQegXwDdOl8AsMM0KWHESgIgjRduoDAcAN06eEECg3QpQsJFBmgSxcRKDZAly4mMMIAXXoEgZEG6NIjCYwyQJceRWC0Abr0aAJjDNClxxAYGwTpuvRYAuMM0KXHERhvgC49nsAEA3TpCQTOMkCXPotAiQG6dAmBiQbo0hMJlBqgS5cSmGSALj2JQJkBunQZgcmVwP9vmAWYTGCKAbr0FAJTDYDSzoFAefBAACZMpQnTzASdfhqB6Qbo9NMJzDBAp59BYKYBOv1MArMM0OlnEZhtgE4/m8AcA3T6OQTmBoHLKdpcAvMM0OnnESg3QG/ycgLzDdCl5xNYYIAuvYDAQgN06YUEFhmgSy8isNgAXXoxgSUG6NJLCCw1QJdeSuDsIHA5NDubwDIDdOllBM4xQJc+h8ByA3Tp5QTONUCXPpfACgN06RUEzjNAlz6PwEoDdOmVBFYZoEuvIrDaAF16NYE1QeByaLaGwPkG6NLnE7jAAF36AgIXGqBLX0hgrQG69FoCFxmgS19EYJ0BuvQ6AusN0KXXE9hggC69gcDFBujSFxPYGAQuh2YbCVxigC59CYFLDdClLyVwmQG69GUENhmgS28icLkBuvTlBDYboEtvJrDFAF16C4GtBujSWwlsM0CX3kbgiiBwOTS7gsCVBujSVxK4ygBd+ioCVxugS19N4BoDdOlrCFxrgC59LYHrDNClryOw3QBdejuBHQbo0jsIXG+ALn09gYogcDk0qyCw0wBdeieBXQbo0rsI3GCALn0Dgd0G6NK7CewxQJfeQ+BGA3TpGwncZIAufROBmw3QpW8mcIsBuvQtBG4NApdDs1sJ3GaALn0bgdsN0KVvJ3CHAbr0HQTuNECXvpPAXQbo0ncR2GuALr2XwN0G6NJ3E7jHAF36HgL3GqBL30vgviBwOTS7j8D9BujS9xN4wABd+gECDxqgSz9I4CEDdOmHCDxsgC79MIFHCpwDgVXBA4HgBJ3+EZrwqPmSOv2jBB4zQKd/jMDjBuj0jxN4IghcTtGeIPCkATr9kwT2GaDT7yPwlAE6/VMEnjZAp3+awDMG6PTPEHjWAF36WQLPGaBLP0fgeQN06ecJvGCALv0CgRcrQYLLKdqLBF4yQJd+icDLBujSLxN4xQBd+hUC+w3QpfcTeNUAXfpVAq8ZoEu/RuB1A3Tp1wkcMECXPkDgDQN06TcIvBkELodmbxJ4ywBd+i0CBw3QpQ8SeNsAXfptAu8YoEu/Q+BdA3Tpdwm8Z4Au/R6B9w3Qpd8n8IEBuvQHBD40QJf+kMBHQeByaPYRgUMG6NKHCHxsgC79MYFPDNClPyFw2ABd+jCBTw3QpT8l8JkBuvRnBD43QJf+nMARA3TpIwS+MECX/oLAl0Hgcmj2JYGvDNClvyLwtQG69NcEvjFAl/6GwLcG6NLfEvjOAF36OwLfG6BLf0/gBwN06R8I/GiALv0jgZ8M0KV/InA0CFwOzY4S+NkAXfpnAscM0KWPEfjFAF36FwK/GqBL/0rgNwN06d8I/G6ALv07gT8M0KX/IHDcAF36OIE/DdCl/yTwVxC4HJr9ReBvA3Tpvwn8Y4Au/Q+Bfw3Qpf8lcMIAXfoEgZMG6NInASRs3lrb4/wXEJ0sIVNbjyASAUTGth5BJBKIzG09gkg1IDK49QgiUYbo0zPrEUSqA5HRrUcQqQFEZrceQaQmEBneegSRaCAyvfUIIrWAyPjWI4h4gej6Xia1gej6tZnUAaLr12FS1ybOgcCm4IGAM0Mvh7o8o575svqIzXoEkfpA9HKozyQGiF4OMUwaANHLoQGThkD0cmjIpBEQvRwaMYkFopdDLJPGQPRyaMykCRC9HJowaQpE12/K5DRD9LGb9QgizYDo+s2YNAei6zdn0gKIrt+CSUsgun5LJq2A6PqtmLQGouu3ZtIGiK7fhkkcEF0/jklbILp+WybtDNEnb9YjiLQHouu3Z9IBiK7fgUlHILp+RyadgOj6nZh0BqLrd2bSBYiu34VJVyC6flcm3YDo+t2YdAei63dncnqQJOrTOOsRRHoA0fV7MOkJRNfvyaQXEF2/F5N4ILp+PBMfEF3fxyQBiK6fwCQRiK6fyCQJiK6fxCQZiK6fzCTFEH1CZz2CSCoQXT+VSRoQXT+NSToQXT+dyRlAdP0zmPQGouv3ZtIHiK7fh0lfILp+Xyb9gOj6/ZicCUTXP5NJf0P0qZ31CCIZQHT9DCaZQHT9TCZZQHT9LCbZQHT9bCYDgOj6A5gMBKLrD2QyCIiuP4jJYCC6/mAmOUB0/RwmQwzRJ3nWI4gMBaLrD2WSC0TXz2WSB0TXz2OSD0TXz2cyDIiuP4xJARBdv4DJcCC6/nAmhUB0/UImRUB0/SImxYbo0z3rEURGANH1RzAZCUTXH8lkFBBdfxST0UB0/dFMxgDR9ccwGQtE1x/LZBwQXX8ck/FAdP3xTCYACdZ3DgQqggcCp8yYwDPOMjP0EaD1CCIlQPRyKGEyEYheDhOZlALRy6GUySQgejlMYlIGRC+HMiaTgejlMJnJFCB6OUxhMhWIXg5TmUwDon8YTGMy3RCX08DpTGYA0fVnMJkJRNefyWQWEF1/FpPZQHT92UzmANH15zCZC0TXn8tkHhBdfx6TciC6fjmT+UB0/flMFhjicvi3gMlCILr+QiaLgOj6i5gsBqLrL2ayBIiuv4TJUiC6/lImZwPR9c9msgyIrr+MyTlAdP1zmCwHousvZ3KuIS6Hf+cyWQFE11/B5Dwguv55TFYC0fVXMlkFRNdfxWQ1EF1/NZM1QHT9NUzOB6Lrn8/kAiC6/gVMLgSi61/IZK0hLod/a5lcBETXv4jJOiC6/jom64Ho+uuZbACi629gcjEQXf9iJhuB6PobmVwCRNe/hMmlQHT9S5lcBkTXv4zJpiBJcjn828TkciC6/uVMNgPR9Tcz2QJE19/CZCsQXX8rk21AdP1tTK4AoutfweRKILr+lUyuAqLrX8XkaiC6/tVMrjHE5fDvGibXAtH1r2VyHRBd/zom24Ho+tuZ7ACi6+9gcj0QXf96JhVAdP0KJjuB6Po7mewCouvvYnIDEF3/Bia7DXE5/NvNZA8QXX8PkxuB6Po3MrkJiK5/E5Obgej6NzO5BYiufwuTW4Ho+rcyuQ2Irn8bk9uB6Pq3M7kDiK5/R0SscyCwN3ggcOqMO80Ml9PAO/nL3gVEL4e7mOwFopfDXiZ3A9HL4W4m9wDRy+EeJvcC0cvhXib3AdHL4T4m9wPRy+F+Jg8A0cvhASYPAtHL4UEmDxnichr4EJOHgej6DzN5BIiu/wiTR4Ho+o8yeQyIrv8Yk8eB6PqPM3kCiK7/BJMngej6TzLZB0TX38fkKSC6/lNMnjbE5fDvaSbPANH1n2HyLBBd/1kmzwHR9Z9j8jwQXf95Ji8A0fVfYPIiEF3/RSYvAdH1X2LyMhBd/2UmrwDR9V9hst8Ql8O//UxeBaLrv8rkNSC6/mtMXgei67/O5AAQXf8AkzeA6PpvMHkTiK7/JpO3gOj6bzE5CETXP8jkbSC6/ttM3jHE5fDvHSbvAtH132XyHhBd/z0m7wPR9d9n8gEQXf8DJh8C0fU/ZPIREF3/IyaHgOj6h5h8DETX/5jJJ0B0/U+YHDbE5fDvMJNPgej6nzL5DIiu/xmTz4Ho+p8zOQJE1z/C5Asguv4XTL4Eout/yeQrILr+V0y+BqLrf83kGyC6/jdMvjXE5fDvWybfAdH1v2PyPRBd/3smPwDR9X9g8iMQXf9HJj8B0fV/YnIUiK5/lMnPQHT9n5kcA6LrH2PyCxBd/xcmvwZJssvh369MfgOi6//G5Hcguv7vTP4Aouv/weQ4EF3/OJM/gej6fzL5C4iu/xeTv4Ho+n8z+QeIrv8Pk3+B6Pr/MjkR4RwI7DP/QqByhstp4AmecdJ8WZfTwJNMPJGG6OXgiSQSAUQvhwgmkUD0cohkUg2IXg7VmEQB0cshikl1IHo5VGdSA4heDjWY1ASil0NNJtGGuJwGRjOpBUTXr8XEC0TX9zKpDUTXr82kDhBdvw6TukB0/bpM6gHR9esxqQ9E16/PJAaIrh/DpAEQXb8Bk4aGuBz+NWTSCIiu34hJLBBdP5ZJYyC6fmMmTYDo+k2YNAWi6zdlchoQXf80Js2A6PrNmDQHous3Z9ICiK7fgklLQ1wO/1oyaQVE12/FpDUQXb81kzZAdP02TOKA6PpxTNoC0fXbMmkHRNdvx6Q9EF2/PZMOQHT9Dkw6AtH1OzLpZIjL4V8nJp2B6PqdmXQBout3YdIViK7flUk3ILp+Nybdgej63ZmcDkTXP51JDyC6fg8mPYHo+j2Z9AKi6/diEm+Iy+FfPBMfEF3fxyQBiK6fwCQRiK6fyCQJiK6fxCQZiK6fzCQFiK6fwiQViK6fyiQNiK6fxiQdiK6fzuQMQ1wO/85g0huIrt+bSR8gun4fJn2B6Pp9mfQDouv3Y3ImEF3/TCb9gej6/ZlkANH1M5hkAtH1M5lkAdH1s5hkG+Jy+JfNZAAQXX8Ak4FAdP2BTAYB0fUHMRkMRNcfzCQHiK6fw2QIEF1/CJOhQHT9oUxygej6uUzygOj6eUzyDXEO/5wDgQPBAwGekc8zhsEMvRyGMSkAopdDAZPhQPRyGM6kEIheDoVMioDo5VDEpBiIXg7FTEYA0cthBJORQPRyGMlkFBC9HEYxGR0kKS6ngaOZjAGi649hMhaIrj+WyTgguv44JuOB6PrjmUwAoutPYHIWEF3/LCYlQHT9EiYTgej6E5mUAtH1S5lMMsTl8G8SkzIgun4Zk8lAdP3JTKYA0fWnMJkKRNefymQaEF1/GpPpQHT96UxmANH1ZzCZCUTXn8lkFhBdfxaT2Ya4HP7NZjIHiK4/h8lcILr+XCbzgOj685iUA9H1y5nMB6Lrz2eyAIiuv4DJQiC6/kImi4Do+ouYLAai6y9mssQQl8O/JUyWAtH1lzI5G4iufzaTZUB0/WVMzgGi65/DZDkQXX85k3OB6PrnMlkBRNdfweQ8ILr+eUxWAtH1VzJZZYjL4d8qJquB6PqrmawBouuvYXI+EF3/fCYXANH1L2ByIRBd/0Ima4Ho+muZXARE17+IyToguv46JuuB6PrrmWwwxOXwbwOTi4Ho+hcz2QhE19/I5BIguv4lTC4FoutfyuQyILr+ZUw2AdH1NzG5HIiufzmTzUB0/c1MtgDR9bcw2WqIy+HfVibbgOj625hcAUTXv4LJlUB0/SuZXAVE17+KydVAdP2rmVwDRNe/hsm1QHT9a5lcB0TXv47JdiC6/nYmOwxxOfxzDgQOBw8EdvCM62GGXg7XM6kAopdDBZOdQPRy2MlkFxC9HHYxuQGIXg43MNkNRC+H3Uz2ANHLYQ+TG4Ho5XAjk5uA6OVwE5ObDXE5DbyZyS1AdP1bmNwKRNe/lcltQHT925jcDkTXv53JHUB0/TuY3AlE17+TyV1AdP27mOwFouvvZXI3EF3/bib3GOLyTwHvYXIvEF3/Xib3AdH172NyPxBd/34mDwDR9R9g8iAQXf9BJg8B0fUfYvIwEF3/YSaPANH1H2HyKBBd/1EmjwVJqsvh32NMHgei6z/O5Akguv4TTJ4Eous/yWQfEF1/H5OngOj6TzF5Goiu/zSTZ4Do+s8weRaIrv8sk+eA6PrPMXneEJfDv+eZvABE13+ByYtAdP0XmbwERNd/icnLQHT9l5m8AkTXf4XJfiC6/n4mrwLR9V9l8hoQXf81Jq8D0fVfZ3LAEJfDvwNM3gCi67/B5E0guv6bTN4Couu/xeQgEF3/IJO3gej6bzN5B4iu/w6Td4Ho+u8yeQ+Irv8ek/eB6PrvM/nAEJfDvw+YfAhE1/+QyUdAdP2PmBwCousfYvIxEF3/YyafANH1P2FyGIiuf5jJp0B0/U+ZfAZE1/+MyedAdP3PmRwxxOXw7wiTL4Do+l8w+RKIrv8lk6+A6PpfMfkaiK7/NZNvgOj63zD5Foiu/y2T74Do+t8x+R6Irv89kx+A6Po/MPnREJfDvx+J+A8EtsVERHjs2xDP0eDJQO2fYJheFz/x1z8KRK+Lo0x+BqLXxc9MjgHR6+IYk1+A6HXxC5Nfgeh18SuT34DodfEbk9+B6HXxO5M/gOh18QeT44a4HAseZ/InEF3/TyZ/AdH1/2LyNxBd/28m/wDR9f9h8i8QXf9fJieA6PonmJwEouufZOKpZoiu76lGJAKIrh/BJNIQl2PBSCbVgOj61ZhEAdH1o5hUB6LrV2dSA4iuX4NJTSC6fk0m0UB0/WgmtYDo+rWYeIHo+l4mtYHo+rWZ1DHE5RSwDpO6QHT9ukzqAdH16zGpD0TXr88kBoiuH8OkARBdvwGThkB0/YZMGgHR9RsxiQWi68cyaQxE12/MpIkhLqeATZg0BaLrN2VyGhBd/zQmzYDo+s2YNAei6zdn0gKIrt+CSUsgun5LJq2A6PqtmLQGouu3ZtIGiK7fhklckKS5nALGMWkLRNdvy6QdEF2/HZP2QHT99kw6ANH1OzDpCETX78ikExBdvxOTzkB0/c5MugDR9bsw6QpE1+/KpJshLqeA3Zh0B6Lrd2dyOhBd/3QmPYDo+j2Y9ASi6/dk0guIrt+LSTwQXT+eiQ+Iru9jkgBE109gkghE109kkmSIyylgEpNkILp+MpMUILp+CpNUILp+KpM0ILp+GpN0ILp+OpMzgOj6ZzDpDUTX782kDxBdvw+TvkB0/b5M+hnicgrYj8mZQKz6zj8V8DSoPBAQM87kGf1hhl4O/ZlkANHLIYNJJhC9HDKZZAHRyyGLSTYQvRyymQwAopfDACYDgejlMJDJICB6OQxiMtgQl2PBwUxygOgfBjlMhgDR9YcwGQpE1x/KJBeIrp/LJA+Irp/HJB+Irp/PZBgQXX8YkwIgun4Bk+FAdP3hTAoNcTkWLGRSBETXL2JSDETXL2YyAoiuP4LJSCC6/kgmo4Do+qOYjAai649mMgaIrj+GyVgguv5YJuOA6PrjmIw3xOXwbzyTCUB0/QlMzgKi65/FpASIrl/CZCIQXX8ik1Igun4pk0lAdP1JTMqA6PplTCYD0fUnM5kCRNefwmSqIS6Hf1OZTAOi609jMh2Irj+dyQwguv4MJjOB6PozmcwCouvPYjIbiK4/m8kcILr+HCZzgej6c5nMA6Lrz2NSbojL4V85k/lAdP35TBYA0fUXMFkIRNdfyGQREF1/EZPFQHT9xUyWANH1lzBZCkTXX8rkbCC6/tlMlgHR9ZcxOccQl8O/c5gsB6LrL2dyLhBd/1wmK4Do+iuYnAdE1z+PyUoguv5KJquA6PqrmKwGouuvZrIGiK6/hsn5QHT985lcECTpLod/FzC5EIiufyGTtUB0/bVMLgKi61/EZB0QXX8dk/VAdP31TDYA0fU3MLkYiK5/MZONQHT9jUwuAaLrX8LkUkNcDv8uZXIZEFHfORCICR4IWDMu4xmbYIZeDpuYXA5EL4fLmWwGopfDZiZbgOjlsIXJViB6OWxlsg2IXg7bmFwBRC+HK5hcCUQvhyuZXGWIy2ngVUyuBqJ/GFzN5Boguv41TK4Foutfy+Q6ILr+dUy2A9H1tzPZAUTX38HkeiC6/vVMKoDo+hVMdgLR9Xcy2WWIy2ngLiY3ANH1b2CyG4iuv5vJHiC6/h4mNwLR9W9kchMQXf8mJjcD0fVvZnILEF3/Fia3AtH1b2VyGxBd/zYmtxvicvh3O5M7gOj6dzC5E4iufyeTu4Do+ncx2QtE19/L5G4guv7dTO4Bouvfw+ReILr+vUzuA6Lr38fkfiC6/v1MHjDE5fDvASYPAtH1H2TyEBBd/yEmDwPR9R9m8ggQXf8RJo8C0fUfZfIYEF3/MSaPA9H1H2fyBBBd/wkmTwLR9Z9kss8Ql8O/fUyeAqLrP8XkaSC6/tNMngGi6z/D5Fkguv6zTJ4Dous/x+R5ILr+80xeAKLrv8DkRSC6/otMXgKi67/E5GVDXA7/XmbyChBd/xUm+4Ho+vuZvApE13+VyWtAdP3XmLwORNd/nckBILr+ASZvANH132DyJhBd/00mbwHR9d9ictAQl8O/g0zeBqLrv83kHSC6/jtM3gWi67/L5D0guv57TN4Houu/z+QDILr+B0w+BKLrf8jkIyC6/kdMDgHR9Q8x+dgQl8O/j5l8AkTX/wSJcyAQFzwQsGcchhl6ORzmL/spEL0cPmXyGRC9HD5j8jkQvRw+Z3IEiF4OR5h8AUQvhy+YfAlEL4cvmXwFRC+Hr5h8XUmGx7ucBn7N5Bsgejl8w+RbILr+t0y+A6Lrf8fkeyC6/vdMfgCi6//A5Ecguv6PTH4Couv/xOQoEF3/KJOfgej6PzM5ZojLaeAxJr8A0fV/YfIrEF3/Vya/AdH1f2PyOxBd/3cmfwDR9f9gchyIrn+cyZ9AdP0/mfwFRNf/i8nfQHT9v5n8Y4jL4d8/TP4Fouv/y+QEEF3/BJOTQHT9k0w8UYbo+p4oIhFAdP0IJpFAdP1IJtWA6PrVmEQB0fWjmFQHoutXZ1LDEJfDvxpMagLR9WsyiQai60czqQVE16/FxAtE1/cyqQ1E16/NpA4QXb8Ok7pAdP26TOoB0fXrMakPRNevzyTGEJfDvxgmDYDo+g2YNASi6zdk0giIrt+ISSwQXT+WSWMgun5jJk2A6PpNmDQFous3ZXIaEF3/NCbNgOj6zZg0N8Tl8K85kxZAdP0WTFoC0fVbMmkFRNdvxaQ1EF2/NZM2QHT9NkzigOj6cUzaAtH12zJpB0TXb8ekPRBdvz2TDoa4HP51YNIRiK7fkUknILp+Jyadgej6nZl0AaLrd2HSFYiu35VJNyC6fjcm3YHo+t2ZnA5E1z+dSQ8gun4PJj0NcTn868mkFxBdvxeTeCDOgUC8ORCQM+J5hg9m6OXgY5IARC+HBCaJQPRySGSSBEQvhyQmyUD0ckhmkgJEL4cUJqlA9HJIZZJmiMtpYBqTdCB6OaQzOQOIrn8Gk95AdP3eTPoA0fX7MOkLRNfvy6QfEF2/H5Mzgej6ZzLpD0TX788kA4iun8Ek0xCX08BMJllAdP0sJtlAdP1sJgOA6PoDmAwEousPZDIIiK4/iMlgILr+YCY5QHT9HCZDgOj6Q5gMBaLrD2WSGyQ+l8O/XCZ5QHT9PCb5QHT9fCbDgOj6w5gUANH1C5gMB6LrD2dSCETXL2RSBETXL2JSDETXL2YyAoiuP4LJSENcDv9GMhkFRNcfxWQ0EF1/NJMxQHT9MUzGAtH1xzIZB0TXH8dkPBBdfzyTCUB0/QlMzgKi65/FpASIrl/CZKIhLod/E5mUAtH1S5lMAqLrT2JSBkTXL2MyGYiuP5nJFCC6/hQmU4Ho+lOZTAOi609jMh2Irj+dyQwguv4MJjMNcTn8m8lkFhBdfxaT2UB0/dlM5gDR9ecwmQtE15/LZB4QXX8ek3Igun45k/lAdP35TBYA0fUXMFkIRNdfyGSRIS6Hf4uYLAai6y9msgSIrr+EyVIguv5SJmcD0fXPZrIMiK6/jMk5QHT9c5gsB6LrL2dyLhBd/1wmK4Do+iuYnGeIy+HfeUxWAtH1VzJZBYTrOwcC/YMHAoEZq3jGapihl8NqJmuA6OWwhsn5QPRyOJ/JBUD0criAyYVA9HK4kMlaIHo5rGVyERC9HC5iss4Ql9PAdUzWA9HLYT2TDUD0D4MNTC4GoutfzGQjEF1/I5NLgOj6lzC5FIiufymTy4Do+pcx2QRE19/E5HIguv7lTDYb4nIauJnJFiC6/hYmW4Ho+luZbAOi629jcgUQXf8KJlcC0fWvZHIVEF3/KiZXA9H1r2ZyDRBd/xom1wLR9a9lcp0hLod/1zHZDkTX385kBxBdfweT64Ho+tczqQCi61cw2QlE19/JZBcQXX8XkxuA6Po3MNkNRNffzWQPEF1/D5MbDXE5/LuRyU1AdP2bmNwMRNe/mcktQHT9W5jcCkTXv5XJbUB0/duY3A5E17+dyR1AdP07mNwJRNe/k8ldQHT9u5jsDZIEl8O/vUzuBqLr383kHiC6/j1M7gWi69/L5D4guv59TO4Houvfz+QBILr+A0weBKLrP8jkISC6/kNMHgai6z/M5BFDXA7/HmHyKBBd/1EmjwHR9R9j8jgQXf9xJk8A0fWfYPIkEF3/SSb7gOj6+5g8BUTXf4rJ00B0/aeZPANE13+GybOGuBz+PcvkOSC6/nNMngei6z/P5AUguv4LTF4Eouu/yOQlILr+S0xeBqLrv8zkFSC6/itM9gPR9fczeRWIrv8qk9cMcTn8e43J60B0/deZHACi6x8IEudAoCB4IODMeANm6OXwBn/ZN4Ho5fAmk7eA6OXwFpODQPRyOMjkbSB6ObzN5B0gejm8w+RdIHo5vMvkPUNcTgPfY/I+EL0c3mfyARC9HD5g8iEQXf9DJh8B0fU/YnIIiK5/iMnHQHT9j5l8AkTX/4TJYSC6/mEmnwLR9T9l8pkhLqeBnzH5HIiu/zmTI0B0/SNMvgCi63/B5Esguv6XTL4Cout/xeRrILr+10y+AaLrf8PkWyC6/rdMvgOi63/H5HtDXA7/vmfyAxBd/wcmPwLR9X9k8hMQXf8nJkeB6PpHmfwMRNf/mckxILr+MSa/ANH1f2HyKxBd/1cmvwHR9X9j8rshLod/vzP5A4iu/weT40B0/eNM/gSi6//J5C8guv5fTP4Gouv/zeQfILr+P0z+BaLr/8vkBBBd/wSTk0B0/ZNMPNWDxOXwz1OdSAQQXT+CSSQQXT+SSTUgun41JlFAdP0oJtWB6PrVmdQAouvXYFITiK5fk0k0EF0/mkktILp+LSZeQ1wO/7xMagPR9WszqQNE16/DpC4QXb8uk3pAdP16TOoD0fXrM4kBouvHMGkARNdvwKQhEF2/IZNGQHT9RkxigyTR5fAvlkljILp+YyZNgOj6TZg0BaLrN2VyGhBd/zQmzYDo+s2YNAei6zdn0gKIrt+CSUsgun5LJq2A6PqtmLQ2xOXwrzWTNkB0/TZM4oDo+nFM2lYS50BgYvBAwJqhl0NbntEOvqxeDu2YtAeil0N7Jh2A6OXQgUlHIHo5dGTSCYheDp2YdAail0NnJl0McTkN7MKkKxC9HLoy6QZEL4duTLoD0fW7MzkdiK5/OpMeQHT9Hkx6AtH1ezLpBUTX78UkHoiuH8/EB0TX9zFJMMTlNDCBSSIQXT+RSRIQXT+JSTIQXT+ZSQoQXT+FSSoQXT+VSRoQXT+NSToQXT+dyRlAdP0zmPQGouv3ZtLHEJfDvz5M+gLR9fsy6QdE1+/H5Ewguv6ZTPoD0fX7M8kAoutnMMkEoutnMskCoutnMckGoutnMxkARNcfwGSgIS6HfwOZDAKi6w9iMhiIrj+YSQ4QXT+HyRAguv4QJkOB6PpDmeQC0fVzmeQB0fXzmOQD0fXzmQwDousPY1JgiMvhXwGT4UB0/eFMCoHo+oVMioDo+kVMioHo+sVMRgDR9UcwGQlE1x/JZBQQXX8Uk9FAdP3RTMYA0fXHMBlriMvh31gm44Do+uOYjAei649nMgGIrj+ByVlAdP2zmJQA0fVLmEwEoutPZFIKRNcvZTIJiK4/iUkZEF2/jMlkQ1wO/yYzmQJE15/CZCoQXX8qk2lAdP1pTKYD0fWnM5kBRNefwWQmEF1/JpNZQHT9WUxmA9H1ZzOZA0TXn8NkriEuh39zmcwDouvPY1IORNcvZzIfyCn1nQOB8uCBQHDGfJ6xAGbo5bCAyUIgejksZLIIiF4Oi5gsBqKXw2ImS4Do5bCEyVIgejksZXJ2kCS5nAaezWQZEL0cljE5B4heDucwWQ5E/zBYzuRcILr+uUxWANH1VzA5D4iufx6TlUB0/ZVMVgHR9VcxWQ1E11/NZI0hLqeBa5icD0TXP5/JBUB0/QuYXAhE17+QyVoguv5aJhcB0fUvYrIOiK6/jsl6ILr+eiYbgOj6G5hcDETXv5jJRkNcDv82MrkEiK5/CZNLgej6lzK5DIiufxmTTUB0/U1MLgei61/OZDMQXX8zky1AdP0tTLYC0fW3MtkGRNffxuQKQ1wO/65gciUQXf9KJlcB0fWvYnI1EF3/aibXANH1r2FyLRBd/1om1wHR9a9jsh2Irr+dyQ4guv4OJtcD0fWvZ1JhiMvhXwWTnUB0/Z1MdgHR9XcxuQGIrn8Dk91AdP3dTPYA0fX3MLkRiK5/I5ObgOj6NzG5GYiufzOTW4Do+rcwudUQl8O/W5ncBkTXv43J7UB0/duZ3AFE17+DyZ1AdP07mdwFRNe/i8leILr+XiZ3A9H172ZyDxBd/x4m9wLR9e9lcp8hLod/9zG5H4iufz+TB4Do+g8weRCIrv8gk4eA6PoPMXkYiK7/MJNHgOj6jzB5FIiu/yiTx4Do+o8xeRyIrv84kycMcTn8e4LJk0B0/SeZ7AOi6+9j8hQQXf+pAHEOBFYFDwTMjKdhhl4OT/OXfQaIXg7PMHkWiF4OzzJ5DoheDs8xeR6IXg7PM3kBiF4OLzB50RCX08AXmbwERC+Hl5i8DEQvh5eZvAJEL4dXmOwHouvvZ/IqEF3/VSavAdH1X2PyOhBd/3UmB4Do+geYvAFE13+DyZuGuJwGvsnkLSC6/ltMDgLR9Q8yeRuIrv82k3eA6PrvMHkXiK7/LpP3gOj67zF5H4iu/z6TD4Do+h8w+RCIrv8hk4+CJNnl8O8jJoeA6PqHmHwMRNf/mMknQHT9T5gcBqLrH2byKRBd/1MmnwHR9T9j8jkQXf9zJkeA6PpHmHwBRNf/gsmXhrgc/n3J5Csguv5XTL4Gout/zeQbILr+N0y+BaLrf8vkOyC6/ndMvgei63/P5Acguv4PTH4Eouv/yOQnILr+T0yOGuJy+HeUyc9AdP2fmRwDousfY/ILEF3/Fya/AtH1f2XyGxBd/zcmvwPR9X9n8gcQXf8PJseB6PrHmfwJRNf/k8lfhrgc/v3F5G8guv7fTP4Bouv/w+RfILr+v0xOANH1TzA5CUTXP8nEU8MQXd9Tg0gEEF0/gkkkEF0/kkk1ILp+NSZRhrgc/kUxqQ5E16/OpAYQXb8Gk5pAdP2aTKKB6PrRTGoB0fVrMfEC0fW9TGoD0fVrM6kDRNevw6QuEF2/LpN6hrgc/tVjUh+Irl+fSQwQXT+GSQMgun4DJg39xDkQ2BQ8EAjM0MuhIc9oBF9WL4dGTGKB6OUQy6QxEL0cGjNpAkQvhyZMmgLRy6Epk9MMcTkNPI1JMyB6OTRj0hyIXg7NmbQAopdDCyYtgej6LZm0AqLrt2LSGoiu35pJGyC6fhsmcUB0/TgmbYHo+m2ZtDPE5TSwHZP2QHT99kw6ANH1OzDpCETX78ikExBdvxOTzkB0/c5MugDR9bsw6QpE1+/KpBsQXb8bk+5AdP3uTE43xOXw73QmPYDo+j2Y9ASi6/dk0guIrt+LSTwQXT+eiQ+Iru9jkgBE109gkghE109kkgRE109ikgxE109mkmKIy+FfCpNUILp+KpM0ILp+GpN0ILp+OpMzgOj6ZzDpDUTX782kDxBdvw+TvkB0/b5M+gHR9fsxOROIrn8mk/5BkuJy+NefSQYQXT+DSSYQXT+TSRYQXT+LSTYQXT+byQAguv4AJgOB6PoDmQwCousPYjIYiK4/mEkOEF0/h8kQQ1wO/4YwGQpE1x/KJBeIrp/LJA+Irp/HJB+Irp/PZBgQXX8YkwIgun4Bk+FAdP3hTAqB6PqFTIqA6PpFTIoNcTn8K2YyAoiuP4LJSCC6/kgmo4Do+qOYjAai649mMgaIrj+GyVgguv5YJuOA6PrjmIwHouuPZzIBiK4/gclZhrgc/p3FpASIrl/CZCIQXX8ik1Igun4pk0lATH3nQKAieCCAMybxjDKYoZdDGZPJQPRymMxkChC9HKYwmQpEL4epTKYB0cthGpPphricBk5nMgOIXg4zmMwEopfDTCazgOjlMIvJbCD6h8FsJnOA6PpzmMwFouvPZTIPiK4/j0k5EF2/nMl8ILr+fCYLDHE5DVzAZCEQXX8hk0VAdP1FTBYD0fUXM1kCRNdfwmQpEF1/KZOzgej6ZzNZBkTXX8bkHCC6/jlMlgPR9ZczOdcQl8O/c5msAKLrr2ByHhBd/zwmK4Ho+iuZrAKi669ishqIrr+ayRoguv4aJucD0fXPZ3IBEF3/AiYXAtH1L2Sy1hCXw7+1TC4CoutfxGQdEF1/HZP1QHT99Uw2ANH1NzC5GIiufzGTjUB0/Y1MLgGi61/C5FIguv6lTC4DoutfxmSTIS6Hf5uYXA5E17+cyWYguv5mJluA6PpbmGwFoutvZbINiK6/jckVQHT9K5hcCUTXv5LJVUB0/auYXA1E17+ayTWGuBz+XcPkWiC6/rVMrgOi61/HZDsQXX87kx1AdP0dTK4Houtfz6QCiK5fwWQnEF1/J5NdQHT9XUxuAKLr38Bkd5Ckuhz+7WayB4iuv4fJjUB0/RuZ3ARE17+Jyc1AdP2bmdwCRNe/hcmtQHT9W5ncBkTXv43J7UB0/duZ3AFE17+DyZ2GuBz+3cnkLiC6/l1M9gLR9fcyuRuIrn83k3uA6Pr3WMQ5ENgbPBA4Zca9MEMvh3v5y94HRC+H+5jcD0Qvh/uZPABEL4cHmDwIRC+HB5k8ZIjLaeBDTB4GopfDw0weAaKXwyNMHgWil8OjTB4DopfDY0weB6LrP87kCSC6/hNMngSi6z/JZB8QXX8fk6eA6PpPMXnaEJfTwKeZPANE13+GybNAdP1nmTwHRNd/jsnzQHT955m8AETXf4HJi0B0/ReZvARE13+JyctAdP2XmbwCRNd/hcl+Q1wO//YzeRWIrv8qk9eA6PqvMXkdiK7/OpMDQHT9A0zeAKLrv8HkTSC6/ptM3gKi67/F5CAQXf8gk7eB6PpvM3nHEJfDv3eYvAtE13+XyXtAdP33mLwPRNd/n8kHQHT9D5h8CETX/5DJR0B0/Y+YHAKi6x9i8jEQXf9jJp8A0fU/YXLYEJfDv8NMPgWi63/K5DMguv5nTD4Hout/zuQIEF3/CJMvgOj6XzD5Eoiu/yWTr4Do+l8x+RqIrv81k2+A6PrfMPnWEJfDv2+ZfAdE1/+OyfdAdP3vmfwARNf/gcmPQHT9H5n8BETX/4nJUSC6/lEmPwPR9X9mcgyIrn+MyS9AdP1fmPxqiMvh369MfgOi6//G5Hcguv7vTP4Aouv/weQ4EF3/OJM/gej6fzL5C4iu/xeTv4Ho+n8z+QeIrv8Pk3+B6Pr/MjlhiMvh3wkmJ4Ho+ieZeGoaout7ahKJAKLrRzCJBKLrRzKpVrPyXwjsCx4IBGfo5VCNZ0TBl9XLIYpJdSB6OVRnUgOIXg41mNQEopdDTSbRQZLmchoYzaQWEL0cajHxAtHLwcukNhC9HGozqQNEL4c6TOoC0fXrMqkHRNevx6Q+EF2/PpMYILp+DJMGQHT9BkwaGuJyGtiQSSMgun4jJrFAdP1YJo2B6PqNmTQBous3YdIUiK7flMlpQHT905g0A6LrN2PSHIiu35xJCyC6fgsmLQ1xOfxryaQVEF2/FZPWQHT91kzaANH12zCJA6LrxzFpC0TXb8ukHRBdvx2T9kB0/fZMOgDR9Tsw6QhE1+/IpJMhLod/nZh0BqLrd2bSBYiu34VJVyC6flcm3YDo+t2YdAei63dncjoQXf90Jj2A6Po9mPQEouv3ZNILiK7fi0m8IS6Hf/FMfEB0fR+TBCC6fgKTRCC6fiKTJCC6fhKTZCC6fjKTFCC6fgqTVCC6fiqTNCC6fhqTdCC6fjqTMwxxOfw7g0lvILp+byZ9gOj6fZj0BaLr92XSD4iu34/JmUB0/TOZ9Aei6/dnkgFE189gkglE189kkgVE189ikm2Iy+FfNpMBQHT9AUwGAtH1BzIZBETXH8RkMBBdfzCTHCC6fg6TIUB0/SFMhgLR9YcyyQWi6+cyyQOi6+cxyTfE5fAvn8kwILr+MCYFQHT9AibDgej6w5kUAtH1C5kUAXHqOwcCB8z/qOCpM4p4RjHM0MuhmMkIIHo5jGAyEoheDiOZjAKil8MoJqMNcTkNHM1kDBC9HMYwGQtEL4exTMYB0cthHJPxQPRyGM9kAhD9w2ACk7OA6PpnMSkBouuXMJkIRNefyKQUiK5fymSSIS6ngZOYlAHR9cuYTAai609mMgWIrj+FyVQguv5UJtOA6PrTmEwHoutPZzIDiK4/g8lMILr+TCazgOj6s5jMDpJ0l8O/2UzmANH15zCZC0TXn8tkHhBdfx6TciC6fjmT+UB0/flMFgDR9RcwWQhE11/IZBEQXX8Rk8VAdP3FTJYY4nL4t4TJUiC6/lImZwPR9c9msgyIrr+MyTlAdP1zmCwHousvZ3IuEF3/XCYrgOj6K5icB0TXP4/JSiC6/komqwxxOfxbxWQ1EF1/NZM1QHT9NUzOB6Lrn8/kAiC6/gVMLgSi61/IZC0QXX8tk4uA6PoXMVkHRNdfx2Q9EF1/PZMNhrgc/m1gcjEQXf9iJhuB6PobmVwCRNe/hMmlQHT9S5lcBkTXv4zJJiC6/iYmlwPR9S9nshmIrr+ZyRYguv4WJlsNcTn828pkGxBdfxuTK4Do+lcwuRKIrn8lk6uA6PpXMbkaiK5/NZNrgOj61zC5Foiufy2T64Do+tcx2Q5E19/OZIchLod/O5hcD0TXv55JBRBdv4LJTiC6/k4mu4Do+ruY3ABE17/BORA4HDwQ4Bm7YYZeDruZ7AGil8MeJjcC0cvhRiY3AdHL4SYmNxvichp4M5NbgOjlcAuTW4Ho5XArk9uA6OVwG5PbgejlcDuTO4Do5XAHkzuB6Pp3MrkLiK5/F5O9QHT9vUzuBqLr383kHkNcTgPvYXIvEF3/Xib3AdH172NyPxBd/34mDwDR9R9g8iAQXf9BJg8B0fUfYvIwEF3/YSaPANH1H2HyKBBd/1Emjxnicvj3GJPHgej6jzN5Aoiu/wSTJ4Ho+k8y2QdE19/H5Ckguv5TTJ4Gous/zeQZILr+M0yeBaLrP8vkOSC6/nNMnjfE5fDveSYvANH1X2DyIhBd/0UmLwHR9V9i8jIQXf9lJq8A0fVfYbIfiK6/n8mrQHT9V5m8BkTXf43J60B0/deZHKgkhfEuh38HmLwBRNd/g8mbQHT9N5m8BUTXf4vJQSC6/kEmbwPR9d9m8g4QXf8dJu8C0fXfZfIeEF3/PSbvA9H132fygSEuh38fMPkQiK7/IZOPgOj6HzE5BETXP8TkYyC6/sdMPgGi63/C5DAQXf8wk0+B6PqfMvkMiK7/GZPPgej6nzM5YojL4d8RJl8A0fW/YPIlEF3/SyZfAdH1v2LyNRBd/2sm3wDR9b9h8i0QXf9bJt8B0fW/Y/I9EF3/eyY/ANH1f2DyoyEuh38/MvkJiK7/E5OjQHT9o0x+BqLr/8zkGBBd/xiTX4Do+r+EHJjZBwLbOsR5/LchnqPBk4FfYZheF7/ysN+A6HXxG5Pfgeh18TuTP4DodfEHk+OGuBwLHmfyJxC9Lv5k8hcQvS7+YvI3EL0u/mbyDxC9Lv5h8i8QvS7+ZXICiK5/gslJILr+SSaeaEN0fU+0IRkFOVkF1iqNaj+ysHhERm5eTlbhsKKBxRHW5/Kc9x7P4RP224g69kf7/PcjvZ5ataz3dT1RNazPRniiIzyBx1bdqm5Vt6pb1a3qVnWrulXdqm5Vt6pb1c3jcf6pgCem8kBgdFF2cR/rQsTb/8X/+RUT48fFDQLvNx9r8P/q+6+6Vd2qblW3qlvVrepWdau6Vd2qblW3qlvVrer2H9z8BwKLe/4vU/1QLw=='

IGVM_MAGIC_VALUE             = 0x4D564749
IGVM_VHT_SUPPORTED_PLATFORM  = 0x1
IGVM_VHT_SNP_POLICY          = 0x101
IGVM_VHT_PARAMETER_AREA      = 0x301
IGVM_VHT_PAGE_DATA           = 0x302
IGVM_VHT_PARAMETER_INSERT    = 0x303
IGVM_VHT_VP_CONTEXT          = 0x304
IGVM_VHT_REQUIRED_MEMORY     = 0x305
IGVM_VHT_SHARED_BOUNDARY_GPA = 0x306
IGVM_VHT_VP_COUNT_PARAMETER  = 0x307
IGVM_VHT_SRAT                = 0x308
IGVM_VHT_MADT                = 0x309
IGVM_VHT_MMIO_RANGES         = 0x30A
IGVM_VHT_SNP_ID_BLOCK        = 0x30B
IGVM_VHT_MEMORY_MAP          = 0x30C
IGVM_VHT_ERROR_RANGE         = 0x30D
IGVM_VHT_COMMAND_LINE        = 0x30E
IGVM_VHT_HCL_SGX_RANGES      = 0x8001

IGVM_VHF_PAGE_DATA_2MB              = 0x1
IGVM_VHF_PAGE_DATA_UNMEASURED       = 0x2

IGVM_VHS_PAGE_DATA_TYPE_NORMAL      = 0x00
IGVM_VHS_PAGE_DATA_TYPE_SECRETS     = 0x01
IGVM_VHS_PAGE_DATA_TYPE_CPUID_DATA  = 0x02
IGVM_VHS_PAGE_DATA_TYPE_CPUID_XF    = 0x03

SNP_PAGE_TYPE_NORMAL     = 1
SNP_PAGE_TYPE_VMSA       = 2
SNP_PAGE_TYPE_ZERO       = 3
SNP_PAGE_TYPE_UNMEASURED = 4
SNP_PAGE_TYPE_SECRETS    = 5
SNP_PAGE_TYPE_CPUID      = 6

CpuIdFunctionBasicMinimum                       = 0x00000000
CpuIdFunctionVendorAndMaxFunction               = 0x00000000
CpuIdFunctionVersionAndFeatures                 = 0x00000001
CpuIdFunctionCacheAndTlbInformation             = 0x00000002
CpuIdFunctionSerialNumber                       = 0x00000003
CpuIdFunctionCacheParameters                    = 0x00000004
CpuIdFunctionMonitorMwait                       = 0x00000005
CpuIdFunctionPowerManagement                    = 0x00000006
CpuIdFunctionExtendedFeatures                   = 0x00000007
CpuIdFunctionDirectCacheAccessParameters        = 0x00000009
CpuIdFunctionPerformanceMonitoring              = 0x0000000A
CpuIdFunctionExtendedTopologyEnumeration        = 0x0000000B
CpuIdFunctionExtendedStateEnumeration           = 0x0000000D
CpuIdFunctionRdtmEnumeration                    = 0x0000000F
CpuIdFunctionRdtaEnumeration                    = 0x00000010
CpuIdFunctionSgxEnumeration                     = 0x00000012
CpuIdFunctionIptEnumeration                     = 0x00000014
CpuIdFunctionCoreCrystalClockInformation        = 0x00000015
CpuIdFunctionNativeModelId                      = 0x0000001A
CpuIdFunctionArchLbr                            = 0x0000001C
CpuIdFunctionTileInformation                    = 0x0000001D
CpuIdFunctionTmulInformation                    = 0x0000001E
CpuIdFunctionV2ExtendedTopologyEnumeration      = 0x0000001F
CpuIdFunctionHistoryResetFeatures               = 0x00000020
CpuIdFunctionBasicMaximum                       = 0x00000020
CpuIdFunctionIntelMaximum                       = 0x00000020
CpuIdFunctionAmdMaximum                         = 0x0000000D
CpuIdFunctionCompatBlueBasicMaximum             = 0x0000000D
CpuIdFunctionGuestBasicMaximum                  = 0x0000001C
CpuIdFunctionUnimplementedMinimum               = 0x40000000
CpuIdFunctionUnimplementedMaximum               = 0x4FFFFFFF
CpuIdFunctionExtendedMinimum                    = 0x80000000
CpuIdFunctionExtendedMaxFunction                = 0x80000000
CpuIdFunctionExtendedVersionAndFeatures         = 0x80000001
CpuIdFunctionExtendedBrandingString1            = 0x80000002
CpuIdFunctionExtendedBrandingString2            = 0x80000003
CpuIdFunctionExtendedBrandingString3            = 0x80000004
CpuIdFunctionExtendedL1CacheParameters          = 0x80000005
CpuIdFunctionExtendedL2CacheParameters          = 0x80000006
CpuIdFunctionExtendedPowerManagement            = 0x80000007
CpuIdFunctionExtendedAddressSpaceSizes          = 0x80000008
CpuIdFunctionExtendedIntelMaximum               = 0x80000008
CpuIdFunctionExtended80000009                   = 0x80000009
CpuIdFunctionExtendedSvmVersionAndFeatures      = 0x8000000A
CpuIdFunctionExtendedTlb1GBIdentifiers          = 0x80000019
CpuIdFunctionExtendedOptimizationIdentifiers    = 0x8000001A
CpuIdFunctionInstructionBasedSamplingProfiler   = 0x8000001B
CpuIdFunctionLightweightProfilingCapabilities   = 0x8000001C
CpuIdFunctionCacheTopologyDefinition            = 0x8000001D
CpuIdFunctionProcessorTopologyDefinition        = 0x8000001E
CpuIdFunctionExtendedSevFeatures                = 0x8000001F
CpuIdFunctionExtendedFeatures2                  = 0x80000021
CpuIdFunctionExtendedAmdMaximum                 = 0x80000021
CpuIdFunctionExtendedMaximum                    = 0x80000021

def dumps(struct):
    assert isinstance(struct, Structure)
    ans = ['{']
    for field_info in struct._fields_:
        field = getattr(struct, field_info[0])
        if isinstance(field, Structure):
            ans.append('%s:' % (field_info[0]))
            ans.append(dumps(field))
        elif type(field) is int:
            ans.append('%s:%s' % (field_info[0], hex(field)))
        elif hasattr(field, '__getitem__'):
            ans.append('%s:%s' % (field_info[0], list(field)))
        else:
            ans.append('%s:%s' % (field_info[0], repr(field)))
    ans.append('}')
    return ' '.join(ans)

# For policy structure check table 20 in https://www.amd.com/system/files/TechDocs/56860.pdf
# SEV Secure Nested Paging Firmware ABI Specification

DEFAULT_POLICY          = 0X20000
DEBUG_BIT_OFFSET        = 19
MIGRATE_MA_BIT_OFFSET   = 18
SMT_BIT_OFFSET          = 16
ABI_MAJOR_OFFSET        = 8
ABI_MINOR_OFFSET        = 0

# sample json
# {
#     "tei_config_name" : "confidential_ml_cvm",
#     "tei_config_version"     : 1,
#     "tei_config_data" : {
#         "version"   : 1,
#         "guest_svn" : 2,
#         "family_id" : "12161A1B12161A1B12161A1B12161A1B",
#         "image_id"  : "1A1B12161A1B12161A1B12161A1B1216",
#         "policy":{
#             "debug_allowed" : false,
#             "migrate_ma"    : false,
#             "smt_allowed"   : true,
#             "abi_major"     : 0,
#             "abi_minor"     : 31
#         }
#     }
# } 

class TEIConfig():
    def __init__(self, file_path = ''):
        if file_path == '': # if no file provided return default values
            self.version    = (c_uint32)(1)
            self.guest_svn  = (c_uint32)(2)
            self.family_id  = (c_uint8 * 16)(1)
            self.image_id   = (c_uint8 * 16)(2)
            self.policy     = (c_uint64)(0x3001f)
            return

        try:
            f = open(file_path, 'r')
        except FileNotFoundError:
            print("Wrong config file path")
        else:
            with f:
                try:
                    data = json.load(f)
                except ValueError: # if data is not in json format
                    print("configuration is not in valid json format")
                else:
                    if not self.is_tei_config_valid(data): # validate config fields
                        raise Exception(" not valid config data ")

                    config_data     = data['tei_config_data']
                    self.version    = (c_uint32)(config_data['version'] if 'version' in config_data.keys() else 1)
                    self.guest_svn  = (c_uint32)(config_data['guest_svn'] if 'guest_svn' in config_data.keys() else 2)
                    if 'family_id' in config_data.keys():
                        family_id_decimal = int(config_data['family_id'], 16)
                        self.family_id  = (c_uint8 * 16)(*list(family_id_decimal.to_bytes(16, 'big')))
                    else:
                        self.family_id = (c_uint8 * 16)(1)

                    if 'image_id' in config_data.keys():
                        image_id_decimal = int(config_data['image_id'], 16)
                        self.image_id = (c_uint8 * 16)(*list(image_id_decimal.to_bytes(16, 'big')))
                    else:
                        self.image_id = (c_uint8 * 16)(2)

                    if 'policy' in config_data.keys():
                        self.policy = (c_uint64)(self.construct_policy(config_data['policy']))
                    else:
                        self.policy = (c_uint64)(0x3001f)
    
    # todo :: all the configuration validations can be added here
    def is_tei_config_valid(self, data):
        return True

    def construct_policy(self, policy_dictionary):
        policy = DEFAULT_POLICY
        if 'debug_allowed' in policy_dictionary.keys():
            policy = policy | policy_dictionary['debug_allowed'] << DEBUG_BIT_OFFSET
        if 'migrate_ma' in policy_dictionary.keys():
            policy = policy | policy_dictionary['migrate_ma'] << MIGRATE_MA_BIT_OFFSET
        if 'smt_allowed' in policy_dictionary.keys():
            policy = policy | policy_dictionary['smt_allowed'] << SMT_BIT_OFFSET
        if 'abi_major' in policy_dictionary.keys():
            policy = policy | policy_dictionary['abi_major'] << ABI_MAJOR_OFFSET
        if 'abi_minor' in policy_dictionary.keys():
            policy = policy | policy_dictionary['abi_minor'] << ABI_MINOR_OFFSET
        return policy

    def __repr__(self):
        repr = "\n============Config details================\n"
        repr += f'Version: {self.version} \n'
        repr += f'Guest SVN: {self.guest_svn} \n'
        repr += f'Family ID: {self.family_id} {cast(self.family_id, c_char_p).value} \n'
        repr += f'Image ID: {self.image_id}, {cast(self.image_id, c_char_p).value} \n'
        repr += f'Policy: {self.policy} hex: {hex(self.policy.value)}\n'
        repr += f'==========================================\n'
        return repr


class setup_header(Structure):
    _pack_ = 1
    _fields_ = [('setup_sects', c_uint8),
                ('root_flags', c_uint16),
                ('syssize', c_uint32),
                ('ram_size', c_uint16),
                ('vid_mode', c_uint16),
                ('root_dev', c_uint16),
                ('boot_flag', c_uint16),
                ('jump', c_uint16),
                ('header', c_uint32),
                ('version', c_uint16),
                ('realmode_swtch', c_uint32),
                ('start_sys_seg', c_uint16),
                ('kernel_version', c_uint16),
                ('type_of_loader', c_uint8),
                ('loadflags', c_uint8),
                ('setup_move_size', c_uint16),
                ('code32_start', c_uint32),
                ('ramdisk_image', c_uint32),
                ('ramdisk_size', c_uint32),
                ('bootsect_kludge', c_uint32),
                ('heap_end_ptr', c_uint16),
                ('ext_loader_ver', c_uint8),
                ('ext_loader_type', c_uint8),
                ('cmd_line_ptr', c_uint32),
                ('initrd_addr_max', c_uint32),
                ('kernel_alignment', c_uint32),
                ('relocatable_kernel', c_uint8),
                ('min_alignment', c_uint8),
                ('xloadflags', c_uint16),
                ('cmdline_size', c_uint32),
                ('hardware_subarch', c_uint32),
                ('hardware_subarch_data', c_uint64),
                ('payload_offset', c_uint32),
                ('payload_length', c_uint32),
                ('setup_data', c_uint64),
                ('pref_address', c_uint64),
                ('init_size', c_uint32),
                ('handover_offset', c_uint32)]

assert sizeof(setup_header) == 0x77

ACPI_END_ADDR = 0x200000

E820_TYPE_RAM           = 1
E820_TYPE_RESERVED      = 2
E820_TYPE_ACPI          = 3
E820_TYPE_NVS           = 4
E820_TYPE_UNUSABLE      = 5
E820_TYPE_PMEM          = 7
E820_TYPE_PRAM          = 12
E820_TYPE_RESERVED_KERN = 128

class boot_e820_entry(Structure):
    _pack_ = 1
    _fields_ = [('addr', c_uint64),
                ('size', c_uint64),
                ('type', c_uint32)]

class efi_info(Structure):
    _pack_ = 1
    _fields_ = [('efi_loader_signature', c_uint32),
                ('efi_systab', c_uint32),
                ('efi_memdesc_size', c_uint32),
                ('efi_memdesc_version', c_uint32),
                ('efi_memmap', c_uint32),
                ('efi_memmap_size', c_uint32),
                ('efi_systab_hi', c_uint32),
                ('efi_memmap_hi', c_uint32)]

class boot_params(Structure):
    _pack_ = 1
    _fields_ = [('screen_info', c_uint8 * 0x40),
                ('apm_bios_info', c_uint8 * 0x14),
                ('_pad2', c_uint8 * 0x4),
                ('tboot_addr', c_uint64),
                ('ist_info', c_uint8 * 0x10),
                ('acpi_rsdp_addr', c_uint64),
                ('_pad3', c_uint8 * 8),
                ('hd0_info', c_uint8 * 16),
                ('hd1_info', c_uint8 * 16),
                ('sys_desc_table', c_uint8 * 0x10),
                ('olpc_ofw_header', c_uint8 * 0x10),
                ('ext_ramdisk_image', c_uint32),
                ('ext_ramdisk_size', c_uint32),
                ('ext_cmd_line_ptr', c_uint32),
                ('_pad4', c_uint8 * 116),
                ('edid_info', c_uint8 * 0x80),
                ('efi_info', efi_info),
                ('alt_mem_k', c_uint32),
                ('scratch', c_uint32),
                ('e820_entries', c_uint8),
                ('eddbuf_entries', c_uint8),
                ('edd_mbr_sig_buf_entries', c_uint8),
                ('kbd_status', c_uint8),
                ('secure_boot', c_uint8),
                ('_pad5', c_uint8 * 2),
                ('sentinel', c_uint8),
                ('_pad6', c_uint8),
                ('hdr', setup_header),
                ('_pad7', c_uint8 * (0x290 - 0x1f1 - sizeof(setup_header))),
                ('edd_mbr_sig_buffer', c_uint32 * 16),
                ('e820_table', boot_e820_entry * 128),
                ('_pad8', c_uint8 * 48),
                ('eddbuf', c_uint8 * 0x1ec),
                ('_pad9', c_uint8 * 276)]

assert sizeof(boot_params) == PGSIZE

class SVM_VMCB_SELECTOR(Structure):
    _pack_ = 1
    _fields_ = [('Selector', c_uint16),
                ('Attrib', c_uint16),
                ('Limit', c_uint32),
                ('Base', c_uint64)]

class HV_UINT128(Structure):
    _pack_ = 1
    _fields_ = [('Low64', c_uint64),
                ('High64', c_uint64)]

class HV_PSP_CPUID_LEAF(Structure):
    _fields_ = [('EaxIn', c_uint32),
                ('EcxIn', c_uint32),
                ('XfemIn', c_uint64),
                ('XssIn', c_uint64),
                ('EaxOut', c_uint32),
                ('EbxOut', c_uint32),
                ('EcxOut', c_uint32),
                ('EdxOut', c_uint32),
                ('ReservedZ', c_uint64)]

class HV_PSP_CPUID_PAGE(Structure):
    _fields_ = [('Count', c_uint32),
                ('ReservedZ1', c_uint32),
                ('ReservedZ2', c_uint64),
                ('CpuidLeafInfo', HV_PSP_CPUID_LEAF * 64)]

class SVM_VMSA(Structure):
    _pack_ = 1
    _fields_ = [('Es', SVM_VMCB_SELECTOR),
                ('Cs', SVM_VMCB_SELECTOR),
                ('Ss', SVM_VMCB_SELECTOR),
                ('Ds', SVM_VMCB_SELECTOR),
                ('Fs', SVM_VMCB_SELECTOR),
                ('Gs', SVM_VMCB_SELECTOR),
                ('Gdtr', SVM_VMCB_SELECTOR),
                ('Ldtr', SVM_VMCB_SELECTOR),
                ('Idtr', SVM_VMCB_SELECTOR),
                ('Tr', SVM_VMCB_SELECTOR),
                ('VmsaReserved1', c_uint8 * 42),
                ('Vmpl', c_uint8),
                ('Cpl', c_uint8),
                ('VmsaReserved2', c_uint32),
                ('Efer', c_uint64),
                ('VmsaReserved3', c_uint32 * 28),
                ('Cr4', c_uint64),
                ('Cr3', c_uint64),
                ('Cr0', c_uint64),
                ('Dr7', c_uint64),
                ('Dr6', c_uint64),
                ('Rflags', c_uint64),
                ('Rip', c_uint64),
                ('Dr0', c_uint64),
                ('Dr1', c_uint64),
                ('Dr2', c_uint64),
                ('Dr3', c_uint64),
                ('Dr0AddrMask', c_uint64),
                ('Dr1AddrMask', c_uint64),
                ('Dr2AddrMask', c_uint64),
                ('Dr3AddrMask', c_uint64),
                ('VmsaReserved4', c_uint64 * 3),
                ('Rsp', c_uint64),
                ('VmsaReserved5', c_uint64 * 3),
                ('Rax', c_uint64),
                ('Star', c_uint64),
                ('Lstar', c_uint64),
                ('Cstar', c_uint64),
                ('Sfmask', c_uint64),
                ('KernelGsBase', c_uint64),
                ('SysenterCs', c_uint64),
                ('SysenterEsp', c_uint64),
                ('SysenterEip', c_uint64),
                ('Cr2', c_uint64),
                ('VmsaReserved6', c_uint64 * 4),
                ('GuestPat', c_uint64),
                ('GuestDbgctl', c_uint64),
                ('GuestLastBranchFromIp', c_uint64),
                ('GuestLastBranchToIp', c_uint64),
                ('GuestLastExcpFromIp', c_uint64),
                ('GuestLastExcpToIp', c_uint64),
                ('VmsaReserved7', c_uint64 * 9),
                ('GuestSpecCtrl', c_uint32),
                ('VmsaReserved8', c_uint32 * 7),
                ('VmsaReserved9', c_uint64),
                ('Rcx', c_uint64),
                ('Rdx', c_uint64),
                ('Rbx', c_uint64),
                ('VmsaReserved10', c_uint64),
                ('Rbp', c_uint64),
                ('Rsi', c_uint64),
                ('Rdi', c_uint64),
                ('R8', c_uint64),
                ('R9', c_uint64),
                ('R10', c_uint64),
                ('R11', c_uint64),
                ('R12', c_uint64),
                ('R13', c_uint64),
                ('R14', c_uint64),
                ('R15', c_uint64),
                ('VmsaReserved11', c_uint64 * 2),
                ('GuestExitInfo1', c_uint64),
                ('GuestExitInfo2', c_uint64),
                ('GuestExitInfo', c_uint64),
                ('GuestNextRip', c_uint64),
                ('SevFeatures', c_uint64),
                ('VIntrCtrl', c_uint64),
                ('GuestExitCode', c_uint64),
                ('VirtualTOM', c_uint64),
                ('GuestTlbID', c_uint64),
                ('GuestPcpuID', c_uint64),
                ('EventInject', c_uint64),
                ('Xfem', c_uint64),
                ('VmsaReserved12', c_uint64 * 2),
                ('LastFpRdp', c_uint64),
                ('Mxcsr', c_uint32),
                ('FpTag', c_uint16),
                ('FpStatus', c_uint16),
                ('FpControl', c_uint16),
                ('FpOp', c_uint16),
                ('LastFpDs', c_uint16),
                ('LastFpCs', c_uint16),
                ('LastFpRip', c_uint64),
                ('FpMmx', c_uint8 * 80),
                ('Xmm0', HV_UINT128),
                ('Xmm1', HV_UINT128),
                ('Xmm2', HV_UINT128),
                ('Xmm3', HV_UINT128),
                ('Xmm4', HV_UINT128),
                ('Xmm5', HV_UINT128),
                ('Xmm6', HV_UINT128),
                ('Xmm7', HV_UINT128),
                ('Xmm8', HV_UINT128),
                ('Xmm9', HV_UINT128),
                ('Xmm10', HV_UINT128),
                ('Xmm11', HV_UINT128),
                ('Xmm12', HV_UINT128),
                ('Xmm13', HV_UINT128),
                ('Xmm14', HV_UINT128),
                ('Xmm15', HV_UINT128),
                ('Ymm0', HV_UINT128),
                ('Ymm1', HV_UINT128),
                ('Ymm2', HV_UINT128),
                ('Ymm3', HV_UINT128),
                ('Ymm4', HV_UINT128),
                ('Ymm5', HV_UINT128),
                ('Ymm6', HV_UINT128),
                ('Ymm7', HV_UINT128),
                ('Ymm8', HV_UINT128),
                ('Ymm9', HV_UINT128),
                ('Ymm10', HV_UINT128),
                ('Ymm11', HV_UINT128),
                ('Ymm12', HV_UINT128),
                ('Ymm13', HV_UINT128),
                ('Ymm14', HV_UINT128),
                ('Ymm15', HV_UINT128),
                ('VmsaReserved12', c_uint64 * 50)]

assert sizeof(SVM_VMSA) == 0x800

class IGVM_FIXED_HEADER(Structure):
    _pack_ = 1
    _fields_ = [('Magic', c_uint32),
                ('FormatVersion', c_uint32),
                ('VariableHeaderOffset', c_uint32),
                ('VariableHeaderSize', c_uint32),
                ('TotalFileSize', c_uint32),
                ('Checksum', c_uint32)]

class IGVM_VHS_VARIABLE_HEADER(Structure):
    _pack_ = 1
    _fields_ = [('Type', c_uint32),
                ('Length', c_uint32)]

class IGVM_VHS_SUPPORTED_PLATFORM(Structure):
    _pack_ = 1
    _fields_ = [('CompatibilityMask', c_uint32),
                ('HighestVtl', c_uint8),
                ('PlatformType', c_uint8),
                ('PlatformVersion', c_uint16),
                ('SharedGPABoundary', c_uint64)]

class IGVM_VHS_SNP_POLICY(Structure):
    _pack_ = 1
    _fields_ = [('Policy', c_uint64),
                ('CompatibilityMask', c_uint32),
                ('Reserved', c_uint32)]

class IGVM_VHS_PARAMETER_AREA(Structure):
    _pack_ = 1
    _fields_ = [('NumberOfBytes', c_uint64),
                ('ParameterAreaIndex', c_uint32),
                ('FileOffset', c_uint32)]

class IGVM_VHS_PAGE_DATA(Structure):
    _pack_ = 1
    _fields_ = [('GPA', c_uint64),
                ('CompatibilityMask', c_uint32),
                ('FileOffset', c_uint32),
                ('Flags', c_uint32),
                ('DataType', c_uint16),
                ('Reserved', c_uint16)]

class IGVM_VHS_PARAMETER_INSERT(Structure):
    _pack_ = 1
    _fields_ = [('GPA', c_uint64),
                ('CompatibilityMask', c_uint32),
                ('ParameterAreaIndex', c_uint32)]

class IGVM_VHS_PARAMETER(Structure):
    _pack_ = 1
    _fields_ = [('ParameterAreaIndex', c_uint32),
                ('ByteOffset', c_uint32)]

class IGVM_VHS_VP_CONTEXT(Structure):
    _pack_ = 1
    _fields_ = [('GPA', c_uint64),
                ('CompatibilityMask', c_uint32),
                ('FileOffset', c_uint32),
                ('VpIndex', c_uint16),
                ('Reserved', c_uint16 * 3)]

class IGVM_VHS_REQUIRED_MEMORY(Structure):
    _pack_ = 1
    _fields_ = [('GPA', c_uint64),
                ('CompatibilityMask', c_uint32),
                ('NumberOfBytes', c_uint32),
                ('Flags', c_uint32),
                ('Reserved', c_uint32)]

IGVM_VHF_REQUIRED_MEMORY_VTL2_PROTECTABLE = 0x1

class IGVM_VHS_MMIO_RANGE(Structure):
    _pack_ = 1
    _fields_ = [('StartingGpaPageNumber', c_uint64),
                ('NumberOfPages', c_uint64)]

class IGVM_VHS_MMIO_RANGES(Structure):
    _pack_ = 1
    _fields_ = [('MmioRanges', IGVM_VHS_MMIO_RANGE * 2)]

class IGVM_VHS_MEMORY_MAP_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [('StartingGpaPageNumber', c_uint64),
                ('NumberOfPages', c_uint64),
                ('Type', c_uint16),
                ('Flags', c_uint16),
                ('Reserved', c_uint32)]

IGVM_VHF_MEMORY_MAP_ENTRY_TYPE_MEMORY            = 0x0
IGVM_VHF_MEMORY_MAP_ENTRY_TYPE_PLATFORM_RESERVED = 0x1
IGVM_VHF_MEMORY_MAP_ENTRY_TYPE_PERSISTENT        = 0x2
IGVM_VHF_MEMORY_MAP_ENTRY_TYPE_VTL2_PROTECTABLE  = 0x3

class IGVM_VHS_SNP_ID_BLOCK_SIGNATURE(Structure):
    _pack_ = 1
    _fields_ = [('R', c_uint8 * 72),
                ('S', c_uint8 * 72)]

class IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY(Structure):
    _pack_ = 1
    _fields_ = [('Curve', c_uint32),
                ('Reserved', c_uint32),
                ('Qx', c_uint8 * 72),
                ('Qy', c_uint8 * 72)]

class IGVM_VHS_SNP_ID_BLOCK(Structure):
    _pack_ = 1
    _fields_ = [('CompatibilityMask', c_uint32),
                ('AuthorKeyEnabled', c_uint8),
                ('Reserved', c_uint8 * 3),
                ('Ld', c_uint8 * 48),
                ('FamilyId', c_uint8 * 16),
                ('ImageId', c_uint8 * 16),
                ('Version', c_uint32),
                ('GuestSvn', c_uint32),
                ('IdKeyAlgorithm', c_uint32),
                ('AuthorKeyAlgorithm', c_uint32),
                ('IdKeySignature', IGVM_VHS_SNP_ID_BLOCK_SIGNATURE),
                ('IdPublicKey', IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY),
                ('AuthorKeySignature', IGVM_VHS_SNP_ID_BLOCK_SIGNATURE),
                ('AuthorPublicKey', IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY)]

class IGVM_VHS_ERROR_RANGE(Structure):
    _pack_ = 1
    _fields_ = [('GPA', c_uint64),
                ('CompatibilityMask', c_uint32),
                ('SizeBytes', c_uint32)]

class SNP_PAGE_INFO(Structure):
    _pack_ = 1
    _fields_ = [('DigestCurrent', c_uint8 * 48),
                ('Contents', c_uint8 * 48),
                ('Length', c_uint16),
                ('PageType', c_uint8),
                ('ImiPageBit', c_uint8),
                ('LowerVmplPermissions', c_uint32),
                ('Gpa', c_uint64)]

class SNP_ID_BLOCK(Structure):
    _pack_ = 1
    _fields_ = [('Ld', c_uint8 * 48),
                ('FamilyId', c_uint8 * 16),
                ('ImageId', c_uint8 * 16),
                ('Version', c_uint32),
                ('GuestSvn', c_uint32),
                ('Policy', c_uint64)]

class TSS32(Structure):
    _pack_ = 1
    _fields_ = [('prev_task_link', c_uint16),
                ('rsvd0', c_uint16),
                ('esp0', c_uint32),
                ('ss0', c_uint16),
                ('rsvd1', c_uint16),
                ('esp1', c_uint32),
                ('ss1', c_uint16),
                ('rsvd2', c_uint16),
                ('esp2', c_uint32),
                ('ss2', c_uint16),
                ('rsvd3', c_uint16),
                ('cr3', c_uint32),
                ('eip', c_uint32),
                ('eflags', c_uint32),
                ('eax', c_uint32),
                ('ecx', c_uint32),
                ('edx', c_uint32),
                ('ebx', c_uint32),
                ('esp', c_uint32),
                ('ebp', c_uint32),
                ('esi', c_uint32),
                ('edi', c_uint32),
                ('es', c_uint16),
                ('rsvd4', c_uint16),
                ('cs', c_uint16),
                ('rsvd5', c_uint16),
                ('ss', c_uint16),
                ('rsvd6', c_uint16),
                ('ds', c_uint16),
                ('rsvd7', c_uint16),
                ('fs', c_uint16),
                ('rsvd8', c_uint16),
                ('gs', c_uint16),
                ('rsvd9', c_uint16),
                ('ldt_selector', c_uint16),
                ('rsvd10', c_uint16),
                ('T', c_uint16, 1),
                ('rsvd11', c_uint16, 15),
                ('io_map_base', c_uint16)]

assert sizeof(TSS32) == 104

class TSS64(Structure):
    _pack_ = 1
    _fields_ = [('rsvd0', c_uint32),
                ('rsp0', c_uint64),
                ('rsp1', c_uint64),
                ('rsp2', c_uint64),
                ('rsvd1', c_uint64),
                ('ist1', c_uint64),
                ('ist2', c_uint64),
                ('ist3', c_uint64),
                ('ist4', c_uint64),
                ('ist5', c_uint64),
                ('ist6', c_uint64),
                ('ist7', c_uint64),
                ('rsvd2', c_uint64),
                ('rsvd3', c_uint16),
                ('io_map_base', c_uint16)]

assert sizeof(TSS64) == 104

class IntGateDesc32(Structure):
    _pack_ = 1
    _fields_ = [('offset0_15', c_uint16),
                ('selector', c_uint16),
                ('rsvd0', c_uint8),
                ('type', c_uint8, 3),
                ('d', c_uint8, 1),
                ('s', c_uint8, 1),
                ('dpl', c_uint8, 2),
                ('p', c_uint8, 1),
                ('offset16_31', c_uint16)]

    def __init__(self, offset = 0, selector = 0, d = 1, dpl = 0, p = 0):
        self.offset0_15 = offset & 0xffff
        self.offset16_31 = (offset >> 16) & 0xffff
        self.selector = selector
        self.type = 0b110
        self.d = d
        self.s = 0
        self.dpl = dpl
        self.p = p

    def offset(self):
        return self.offset0_15 | (self.offset16_31 << 16)

assert sizeof(IntGateDesc32) == 8

class IntGateDesc64(IntGateDesc32):
    _pack_ = 1
    _fields_ = [('offset32_63', c_uint32),
                ('rsvd', c_uint32)]

    def __init__(self, offset = 0, selector = 0, d = 1, dpl = 0, p = 0):
        self.offset32_63 = (offset >> 32) & 0xffffffff
        IntGateDesc32.__init__(self, offset & 0xffffffff, selector, d, dpl, p)

    def offset(self):
        return IntGateDesc32.offset(self) | (self.offset32_63 << 32)

assert sizeof(IntGateDesc64) == 16

class TrapGateDesc32(IntGateDesc32):
    def __init__(self, offset = 0, selector = 0, d = 1, dpl = 0, p = 0):
        IntGateDesc32.__init__(self, offset, selector, d, dpl, p)
        self.type = 0b111

assert sizeof(TrapGateDesc32) == 8

class TrapGateDesc64(TrapGateDesc32):
    _pack_ = 1
    _fields_ = [('offset32_63', c_uint32),
                ('rsvd', c_uint32)]

    def __init__(self, offset = 0, selector = 0, d = 1, dpl = 0, p = 0):
        self.offset32_63 = (offset >> 32) & 0xffffffff
        TrapGateDesc32.__init__(self, offset & 0xffffffff, selector, d, dpl, p)

    def offset(self):
        return TrapGateDesc32.offset(self) | (self.offset32_63 << 32)

assert sizeof(TrapGateDesc64) == 16

class CallGateDesc32(Structure):
    _pack_ = 1
    _fields_ = [('offset0_15', c_uint16),
                ('selector', c_uint16),
                ('param_count', c_uint8, 5),
                ('rsvd0', c_uint8, 3),
                ('type', c_uint8, 4),
                ('s', c_uint8, 1),
                ('dpl', c_uint8, 2),
                ('p', c_uint8, 1),
                ('offset16_31', c_uint16)]

    def __init__(self, offset = 0, selector = 0, param_count = 0, dpl = 0, p = 0):
        self.offset0_15 = offset & 0xffff
        self.offset16_31 = (offset >> 16) & 0xffff
        self.selector = selector
        self.type = 0b1100
        self.s = 0
        self.param_count = param_count
        self.dpl = dpl
        self.p = p

    def offset(self):
        return self.offset0_15 | (self.offset16_31 << 16)

assert sizeof(CallGateDesc32) == 8

class CallGateDesc64(CallGateDesc32):
    _pack_ = 1
    _fields_ = [('offset32_63', c_uint32),
                ('rsvd', c_uint32)]

    def __init__(self, offset = 0, selector = 0, param_count = 0, dpl = 0, p = 0):
        self.offset32_63 = (offset >> 32) & 0xffffffff
        CallGateDesc32.__init__(self, offset & 0xffffffff, selector, param_count, dpl, p)

    def offset(self):
        return CallGateDesc32.offset(self) | (self.offset32_63 << 32)

assert sizeof(CallGateDesc64) == 16

class TaskGateDesc32(Structure):
    _pack_ = 1
    _fields_ = [('rsvd0', c_uint16),
                ('selector', c_uint16),
                ('rsvd1', c_uint8),
                ('type', c_uint8, 4),
                ('s', c_uint8, 1),
                ('dpl', c_uint8, 2),
                ('p', c_uint8, 1),
                ('rsvd2', c_uint16)]

    def __init__(self, selector = 0, dpl = 0, p = 0):
        self.selector = selector
        self.type = 0b0101
        self.dpl = dpl
        self.p = p

assert sizeof(TaskGateDesc32) == 8

class SegDesc32(Structure):
    _pack_ = 1
    _fields_ = [('limit0_15', c_uint16),
                ('base0_15', c_uint16),
                ('base16_23', c_uint8),
                ('type', c_uint8, 4),
                ('s', c_uint8, 1),
                ('dpl', c_uint8, 2),
                ('p', c_uint8, 1),
                ('limit16_19', c_uint8, 4),
                ('avl', c_uint8, 1),
                ('l', c_uint8, 1),
                ('db', c_uint8, 1),
                ('g', c_uint8, 1),
                ('base24_31', c_uint8)]

    def __init__(self, base = 0, limit = 0, type = 0, s = 0, dpl = 0, p = 0, avl = 0, l = 0, db = 0, g = 0):
        self.base0_15 = base & 0xffff
        self.base16_23 = (base >> 16) & 0xff
        self.base24_31 = (base >> 24) & 0xff
        self.limit0_15 = limit & 0xffff
        self.limit16_19 = (limit >> 16) & 0xf
        self.type = type
        self.s = s
        self.dpl = dpl
        self.p = p
        self.avl = avl
        self.l = l
        self.db = db
        self.g = g

    def base(self):
        return self.base0_15 | (self.base16_23 << 16) | (self.base24_31 << 24)

    def limit(self):
        return self.limit0_15 | (self.limit16_19 << 16)

assert sizeof(SegDesc32) == 8

class TssDesc32(SegDesc32):
    def __init__(self, base = 0, limit = 0, b = 0, dpl = 0, p = 0, avl = 0, g = 0):
        type = 0b1001 | (b << 1)
        SegDesc32.__init__(self, base, limit, type, 0, dpl, p, avl, 0, 0, g)

assert sizeof(TssDesc32) == 8

class TssDesc64(TssDesc32):
    _pack_ = 1
    _fields_ = [('base32_63', c_uint32),
                ('rsvd', c_uint32)]

    def __init__(self, base = 0, limit = 0, b = 0, dpl = 0, p = 0, avl = 0, g = 0):
        self.base32_63 = (base >> 32) & 0xffffffff
        TssDesc32.__init__(self, base & 0xffffffff, limit, b, dpl, p, avl, g)

    def base(self):
        return TssDesc32.base(self) | (self.base32_63 << 32)

assert sizeof(TssDesc64) == 16

class PDE32(Structure):
    _pack_ = 1
    _fields_ = [('p', c_uint32, 1),
                ('w', c_uint32, 1),
                ('u', c_uint32, 1),
                ('pwt', c_uint32, 1),
                ('pcd', c_uint32, 1),
                ('a', c_uint32, 1),
                ('rsvd0', c_uint32, 1),
                ('ps', c_uint32, 1),
                ('rsvd1', c_uint32, 4),
                ('pfn', c_uint32, 20)]

assert sizeof(PDE32) == 4

class PTE32(Structure):
    _pack_ = 1
    _fields_ = [('p', c_uint32, 1),
                ('w', c_uint32, 1),
                ('u', c_uint32, 1),
                ('pwt', c_uint32, 1),
                ('pcd', c_uint32, 1),
                ('a', c_uint32, 1),
                ('d', c_uint32, 1),
                ('pat', c_uint32, 1),
                ('g', c_uint32, 1),
                ('rsvd1', c_uint32, 3),
                ('pfn', c_uint32, 20)]

assert sizeof(PTE32) == 4

class PML4E(Structure):
    _pack_ = 1
    _fields_ = [('p', c_uint64, 1),
                ('w', c_uint64, 1),
                ('u', c_uint64, 1),
                ('pwt', c_uint64, 1),
                ('pcd', c_uint64, 1),
                ('a', c_uint64, 1),
                ('rsvd0', c_uint64, 6),
                ('pfn', c_uint64, 40),
                ('rsvd1', c_uint64, 11),
                ('xd', c_uint64, 1)]

assert sizeof(PML4E) == 8

class PDPTE(Structure):
    _pack_ = 1
    _fields_ = [('p', c_uint64, 1),
                ('w', c_uint64, 1),
                ('u', c_uint64, 1),
                ('pwt', c_uint64, 1),
                ('pcd', c_uint64, 1),
                ('a', c_uint64, 1),
                ('d', c_uint64, 1),
                ('ps', c_uint64, 1),
                ('g', c_uint64, 1),
                ('rsvd0', c_uint64, 3),
                ('pfn', c_uint64, 40),
                ('rsvd1', c_uint64, 11),
                ('xd', c_uint64, 1)]

assert sizeof(PDPTE) == 8

class PDE64(Structure):
    _pack_ = 1
    _fields_ = [('p', c_uint64, 1),
                ('w', c_uint64, 1),
                ('u', c_uint64, 1),
                ('pwt', c_uint64, 1),
                ('pcd', c_uint64, 1),
                ('a', c_uint64, 1),
                ('rsvd0', c_uint64, 1),
                ('ps', c_uint64, 1),
                ('rsvd1', c_uint64, 4),
                ('pfn', c_uint64, 40),
                ('rsvd2', c_uint64, 11),
                ('xd', c_uint64, 1)]

assert sizeof(PDE64) == 8

class PTE64(Structure):
    _pack_ = 1
    _fields_ = [('p', c_uint64, 1),
                ('w', c_uint64, 1),
                ('u', c_uint64, 1),
                ('pwt', c_uint64, 1),
                ('pcd', c_uint64, 1),
                ('a', c_uint64, 1),
                ('d', c_uint64, 1),
                ('pat', c_uint64, 1),
                ('g', c_uint64, 1),
                ('rsvd0', c_uint64, 3),
                ('pfn', c_uint64, 40),
                ('rsvd2', c_uint64, 7),
                ('pkey', c_uint64, 4),
                ('xd', c_uint64, 1)]

assert sizeof(PTE64) == 8

class RegCr0(Structure):
    _pack_ = 1
    _fields_ = [('PE', c_uint32, 1),
                ('MP', c_uint32, 1),
                ('EM', c_uint32, 1),
                ('TS', c_uint32, 1),
                ('ET', c_uint32, 1),
                ('NE', c_uint32, 1),
                ('rsvd0', c_uint32, 10),
                ('WP', c_uint32, 1),
                ('rsvd1', c_uint32, 1),
                ('AM', c_uint32, 1),
                ('rsvd2', c_uint32, 10),
                ('NW', c_uint32, 1),
                ('CD', c_uint32, 1),
                ('PG', c_uint32, 1)]

assert sizeof(RegCr0) == 4

class RegCr4(Structure):
    _pack_ = 1
    _fields_ = [('VME', c_uint32, 1),
                ('PVI', c_uint32, 1),
                ('TSD', c_uint32, 1),
                ('DE', c_uint32, 1),
                ('PSE', c_uint32, 1),
                ('PAE', c_uint32, 1),
                ('MCE', c_uint32, 1),
                ('PGE', c_uint32, 1),
                ('PCE', c_uint32, 1),
                ('OSFXSR', c_uint32, 1),
                ('OSXMMEXCPT', c_uint32, 1),
                ('UMIP', c_uint32, 1),
                ('rsvd0', c_uint32, 1),
                ('VMXE', c_uint32, 1),
                ('SMXE', c_uint32, 1),
                ('rsvd1', c_uint32, 1),
                ('FSGSBASE', c_uint32, 1),
                ('PCIDE', c_uint32, 1),
                ('OSXSAVE', c_uint32, 1),
                ('rsvd2', c_uint32, 1),
                ('SMEP', c_uint32, 1),
                ('SMAP', c_uint32, 1),
                ('PKE', c_uint32, 1),
                ('rsvd3', c_uint32, 9)]

assert sizeof(RegCr4) == 4

class RegEflags(Structure):
    _pack_ = 1
    _fields_ = [('CF', c_uint32, 1),
                ('one', c_uint32, 1),
                ('PF', c_uint32, 1),
                ('rsvd0', c_uint32, 1),
                ('AF', c_uint32, 1),
                ('rsvd1', c_uint32, 1),
                ('ZF', c_uint32, 1),
                ('SF', c_uint32, 1),
                ('TF', c_uint32, 1),
                ('IF', c_uint32, 1),
                ('DF', c_uint32, 1),
                ('OF', c_uint32, 1),
                ('IOPL', c_uint32, 2),
                ('NT', c_uint32, 1),
                ('rsvd2', c_uint32, 1),
                ('RF', c_uint32, 1),
                ('VM', c_uint32, 1),
                ('AC', c_uint32, 1),
                ('VIF', c_uint32, 1),
                ('VIP', c_uint32, 1),
                ('ID', c_uint32, 1),
                ('rsvd3', c_uint32, 10)]

    def __init__(self):
        self.one = 1

assert sizeof(RegEflags) == 4

class RegEfer(Structure):
    _fields_ = [('SCE', c_uint32, 1),
                ('rsvd0', c_uint32, 7),
                ('LME', c_uint32, 1),
                ('rsvd1', c_uint32, 1),
                ('LMA', c_uint32, 1),
                ('NXE', c_uint32, 1),
                ('SVME', c_uint32, 1),
                ('rsvd2', c_uint32, 19)]

assert sizeof(RegEfer) == 4

class Reg32(Structure):
    _fields_ = [('value', c_uint32)]

assert sizeof(Reg32) == 4

class Reg64(Structure):
    _pack_ = 1
    _fields_ = [('value', c_uint64)]

assert sizeof(Reg64) == 8

class Reg128(Structure):
    _pack_ = 1
    _fields_ = [('low', c_uint64),
                ('high', c_uint64)]

assert sizeof(Reg128) == 16

class RegTable32(Structure):
    _pack_ = 1
    _fields_ = [('base', c_uint32),
                ('limit', c_uint16)]

assert sizeof(RegTable32) == 6

class RegTable64(Structure):
    _pack_ = 1
    _fields_ = [('base', c_uint64),
                ('limit', c_uint16)]

assert sizeof(RegTable64) == 10

class RegSeg32(Structure):
    _pack_ = 1
    _fields_ = [('base', c_uint32),
                ('limit', c_uint32),
                ('selector', c_uint16),
                ('type', c_uint16, 4),
                ('s', c_uint16, 1),
                ('dpl', c_uint16, 2),
                ('p', c_uint16, 1),
                ('rsvd0', c_uint16, 4),
                ('avl', c_uint16, 1),
                ('l', c_uint16, 1),
                ('db', c_uint16, 1),
                ('g', c_uint16, 1)]

assert sizeof(RegSeg32) == 12

class RegSeg64(Structure):
    _pack_ = 1
    _fields_ = [('base', c_uint64),
                ('limit', c_uint32),
                ('selector', c_uint16),
                ('type', c_uint16, 4),
                ('s', c_uint16, 1),
                ('dpl', c_uint16, 2),
                ('p', c_uint16, 1),
                ('rsvd0', c_uint16, 4),
                ('avl', c_uint16, 1),
                ('l', c_uint16, 1),
                ('db', c_uint16, 1),
                ('g', c_uint16, 1)]

    def attrib(self):
        return self.type | (self.s << 4) | (self.dpl << 5) | (self.p << 7) | (self.avl << 8) | (self.l << 9) | (self.db << 10) | (self.g << 11)

assert sizeof(RegSeg64) == 16

class RegFile(Structure):
    _pack_ = 1
    _fields_ = [('rax', Reg64),
                ('rcx', Reg64),
                ('rdx', Reg64),
                ('rbx', Reg64),
                ('rsp', Reg64),
                ('rbp', Reg64),
                ('rsi', Reg64),
                ('rdi', Reg64),
                ('r8', Reg64),
                ('r9', Reg64),
                ('r10', Reg64),
                ('r11', Reg64),
                ('r12', Reg64),
                ('r13', Reg64),
                ('r14', Reg64),
                ('r15', Reg64),
                ('rip', Reg64),
                ('eflags', RegEflags),
                ('es', RegSeg64),
                ('cs', RegSeg64),
                ('ss', RegSeg64),
                ('ds', RegSeg64),
                ('fs', RegSeg64),
                ('gs', RegSeg64),
                ('tr', RegSeg64),
                ('idtr', RegTable64),
                ('gdtr', RegTable64),
                ('cr0', RegCr0),
                ('cr2', Reg64),
                ('cr3', Reg64),
                ('cr4', RegCr4),
                ('dr0', Reg64),
                ('dr1', Reg64),
                ('dr2', Reg64),
                ('dr3', Reg64),
                ('dr6', Reg32),
                ('dr7', Reg32),
                ('sysentercs', Reg32),
                ('sysentereip', Reg64),
                ('sysenteresp', Reg64),
                ('efer', RegEfer),
                ('kernelgsbase', Reg64),
                ('star', Reg64),
                ('lstar', Reg64),
                ('cstar', Reg64),
                ('sfmask', Reg32)]

    def __init__(self):
        for field_info in self._fields_:
            setattr(self, field_info[0], field_info[1]())

class Memory(bytearray):
    def allocate(self, size, alignment = 1):
        addr = (len(self) + alignment - 1) // alignment * alignment
        self.extend(b'\x00' * (addr + size - len(self)))
        return addr

    def write(self, addr, content):
        assert addr + len(content) <= len(self)
        self[addr:addr + len(content)] = content

    def read(self, addr, size):
        assert addr + size <= len(self)
        return self[addr:addr + size]

class VMState(object):
    def __init__(self, arch = 0x86):
        assert arch in (0x86, 0x64), 'Unsupported architecture: %x' % arch
        self.memory = Memory()
        self.regs = RegFile()
        self.regs.cr0.PE = 1
        if arch == 0x64:
            self.regs.efer.SCE = 1
            self.regs.efer.LME = 1
            self.regs.efer.LMA = 1
            self.regs.efer.NXE = 1

    def setup_acpi(self):
        # [0-0xa0000] is reserved for BIOS
        # [0xe0000 - 0x200000] is for ACPI related data
        # load ACPI pages
        acpi = pickle.loads(zlib.decompress(base64.b64decode(ACPI)))
        sorted_gpa = list(acpi.keys())
        sorted_gpa.sort()
        for gpa in sorted_gpa:
            assert(gpa < ACPI_END_ADDR)
            self.seek(gpa)
            self.memory.allocate(PGSIZE)
            self.memory.write(gpa, acpi[gpa]) 

    def setup_real(self):
        '''
        Setup registers for real-mode execution.
        '''
        assert self.regs.efer.LMA == 0
        # setup segment selector registers
        for (reg, s, type) in [(self.regs.cs, 1, 0b1011),
                               (self.regs.ds, 1, 0b0011),
                               (self.regs.es, 1, 0b0011),
                               (self.regs.fs, 1, 0b0011),
                               (self.regs.gs, 1, 0b0011),
                               (self.regs.ss, 1, 0b0011),
                               (self.regs.tr, 0, 0b1011)]:
            reg.limit = 0xffff
            reg.type = type
            reg.s = s
            reg.p = 1
        # setup table registers
        for reg in [self.regs.idtr, self.regs.gdtr]:
            reg.limit = 0xffff
        # disable protected mode
        self.regs.cr0.PE = 0

    def setup_paging(self):
        '''
        Setup an identity mapping (VA == PA) with full accesses.
        '''
        assert self.regs.cr0.PG == 0
        if self.regs.efer.LMA == 0:
            # allocate a page table directory
            pgdiraddr = self.memory.allocate(PGSIZE, PGSIZE)
            # setup identity mapping for [0, 4GB)
            for i in range(PGSIZE // sizeof(PDE32)):
                pde = PDE32.from_buffer(self.memory, pgdiraddr + i * sizeof(PDE32))
                pde.p = 1
                pde.w = 1
                pde.u = 1
                pde.ps = 1 # mark as a 4MB large page
                pde.pfn = (i << 10)
            # setup cr3
            self.regs.cr3.value = pgdiraddr
        else:
            # allocate a PML4 and a PDPT
            pml4addr = self.memory.allocate(PGSIZE, PGSIZE)
            pdptaddr = self.memory.allocate(PGSIZE, PGSIZE)
            # make the first PML4 entry point to the PDPT
            pml4e = PML4E.from_buffer(self.memory, pml4addr)
            pml4e.p = 1
            pml4e.w = 1
            pml4e.u = 1
            pml4e.pfn = (pdptaddr >> 12)
            # setup identity mapping for [0, 512GB)
            for i in range(PGSIZE // sizeof(PDPTE)):
                pdpte = PDPTE.from_buffer(self.memory, pdptaddr + i * sizeof(PDPTE))
                pdpte.p = 1
                pdpte.w = 1
                pdpte.u = 1
                pdpte.ps = 1 # mark as a 1GB large page (requires hardware support)
                pdpte.pfn = (i << 18)
            # PAE is required for 4-level paging
            self.regs.cr4.PAE = 1
            # setup cr3
            self.regs.cr3.value = pml4addr
        # enable large page support
        self.regs.cr4.PSE = 1
        # turn on paging
        self.regs.cr0.PG = 1

    def load_seg(self, reg, selector):
        '''
        Load the segment register and update its cache accordingly.
        '''
        assert (selector & 0b100) == 0, 'LDT is not supported yet'
        assert selector + sizeof(SegDesc32) - 1 <= self.regs.gdtr.limit
        desc_addr = self.regs.gdtr.base + (selector & ~0b111)
        desc = SegDesc32.from_buffer(self.memory, desc_addr)
        if desc.s == 0:
            if desc.type == 0b1100:
                desc = (CallGateDesc64 if self.regs.efer.LMA else CallGateDesc32).from_buffer(self.memory, desc_addr)
            elif desc.type == 0b1011 or desc.type == 0b1001:
                desc = (TssDesc64 if self.regs.efer.LMA else TssDesc32).from_buffer(self.memory, desc_addr)
            else:
                raise NotImplementedError
        reg.base = desc.base()
        reg.limit = desc.limit() if not desc.g else (desc.limit() * PGSIZE + PGSIZE - 1)
        reg.selector = selector
        reg.type = desc.type
        reg.s = desc.s
        reg.dpl = desc.dpl
        reg.p = desc.p
        reg.avl = desc.avl
        reg.l = desc.l
        reg.db = desc.db
        reg.g = desc.g

    def setup_gdt(self):
        '''
        Setup the Global Descriptor Table (GDT) using flat memory model.
        The constructed GDT will be like [NULL, KT, UT, KD, UD, TSS], and
        all the segment registers are initialized to refer to KT/KD.
        If you wish to setup a customized GDT, please do it yourself.
        '''
        assert self.regs.gdtr.base == 0
        assert self.regs.gdtr.limit == 0
        # create a task state segment
        long_mode = self.regs.efer.LMA
        tss_size = sizeof(TSS32) if long_mode else sizeof(TSS64)
        tss_addr = self.memory.allocate(tss_size)
        # GDT always starts with a NULL descriptor
        gdt = [SegDesc32(), # NULL
               SegDesc32(0, 0xfffff, 0b1011, 1, 0, 1, 0, long_mode, 1 - long_mode, 1), # KT
               SegDesc32(0, 0xfffff, 0b1011, 1, 3, 1, 0, long_mode, 1 - long_mode, 1), # UT
               SegDesc32(0, 0xfffff, 0b0011, 1, 0, 1, 0, 0, 1, 1), # KD
               SegDesc32(0, 0xfffff, 0b0011, 1, 3, 1, 0, 0, 1, 1)] # UD
        # add a TSS descriptor to GDT based on the arch
        if long_mode:
            gdt.append(TssDesc64(tss_addr, tss_size - 1, 1, 0, 1, 0, 0))
        else:
            gdt.append(TssDesc32(tss_addr, tss_size - 1, 1, 0, 1, 0, 0))
        # allocate GDT from the memory
        gdt_size = sum([sizeof(desc) for desc in gdt])
        gdt_addr = self.memory.allocate(gdt_size)
        # initialize the GDT layout accordingly
        self.memory.write(gdt_addr, b''.join([bytearray(desc) for desc in gdt]))
        # update gdtr to point to the GDT in memory
        self.regs.gdtr.base = gdt_addr
        self.regs.gdtr.limit = gdt_size - 1
        # update segment registers
        self.load_seg(self.regs.cs, 0x8)
        self.load_seg(self.regs.ds, 0x18)
        self.load_seg(self.regs.es, 0x18)
        self.load_seg(self.regs.ss, 0x18)
        self.load_seg(self.regs.tr, 0x28)

    def setup_idt(self, descs):
        '''
        Setup the Interrupt Descriptor Table given a list of IDT descriptors.
        '''
        # convert the descriptors into raw bytes
        raw = ''.join([str(bytearray(desc)) for desc in descs])
        # allocate IDT and set it up accordingly
        idt_size = len(raw)
        idt_addr = self.memory.allocate(idt_size, 8)
        self.memory.write(idt_addr, raw)
        # update idtr to point to the IDT
        self.regs.idtr.base = idt_addr
        self.regs.idtr.limit = idt_size - 1

class IGVMFile(VMState):
    def __init__(self, config, sign_key):
        VMState.__init__(self, 0x86)
        self.skipped_regions = []
        self.regs.efer.SVME = 1
        self.config = config
        self.sign_key = sign_key

    def seek(self, addr):
        assert addr & ~(PGSIZE - 1) == addr
        end = self.memory.allocate(0)
        assert addr >= end
        if addr > end:
            self.skipped_regions.append((end, addr))
            self.memory.allocate(addr - end)

    def is_skipped(self, addr):
        for (start, end) in self.skipped_regions:
            if start <= addr < end:
                return True
        return False

    @staticmethod
    def dump(raw):
        header = IGVM_FIXED_HEADER.from_buffer(raw, 0)
        print(dumps(header))
        offset = header.VariableHeaderOffset
        while offset < header.VariableHeaderOffset + header.VariableHeaderSize:
            varheader = IGVM_VHS_VARIABLE_HEADER.from_buffer(raw, offset)
            if varheader.Type == IGVM_VHT_SUPPORTED_PLATFORM:
                print('IGVM_VHT_SUPPORTED_PLATFORM(%x)' % offset, dumps(IGVM_VHS_SUPPORTED_PLATFORM.from_buffer(raw, offset + sizeof(varheader))))
            elif varheader.Type == IGVM_VHT_SNP_POLICY:
                print('IGVM_VHT_SNP_POLICY(%x)' % offset, dumps(IGVM_VHS_SNP_POLICY.from_buffer(raw, offset + sizeof(varheader))))
            elif varheader.Type == IGVM_VHT_PARAMETER_AREA:
                print('IGVM_VHT_PARAMETER_AREA(%x)' % offset, dumps(IGVM_VHS_PARAMETER_AREA.from_buffer(raw, offset + sizeof(varheader))))
            elif varheader.Type == IGVM_VHT_PAGE_DATA:
                pagedata = IGVM_VHS_PAGE_DATA.from_buffer(raw, offset + sizeof(varheader))
                print('IGVM_VHT_PAGE_DATA(%x)' % offset, dumps(pagedata))
            elif varheader.Type == IGVM_VHT_PARAMETER_INSERT:
                param_insert = IGVM_VHS_PARAMETER_INSERT.from_buffer(raw, offset + sizeof(varheader))
                print('IGVM_VHT_PARAMETER_INSERT(%x)' % offset, dumps(param_insert))
            elif varheader.Type == IGVM_VHT_VP_CONTEXT:
                context = IGVM_VHS_VP_CONTEXT.from_buffer(raw, offset + sizeof(varheader))
                vmsa = SVM_VMSA.from_buffer(raw, context.FileOffset)
                print('IGVM_VHT_VP_CONTEXT(%x)' % offset, dumps(context), dumps(vmsa))
            elif varheader.Type == IGVM_VHT_REQUIRED_MEMORY:
                print('IGVM_VHT_REQUIRED_MEMORY(%x)' % offset, dumps(IGVM_VHS_REQUIRED_MEMORY.from_buffer(raw, offset + sizeof(varheader))))
            elif varheader.Type == IGVM_VHT_SHARED_BOUNDARY_GPA:
                print('IGVM_VHT_SHARED_BOUNDARY_GPA(%x)' % offset)
            elif varheader.Type == IGVM_VHT_VP_COUNT_PARAMETER:
                print('IGVM_VHT_VP_COUNT_PARAMETER(%x)' % offset, dumps(IGVM_VHS_PARAMETER.from_buffer(raw, offset + sizeof(varheader))))
            elif varheader.Type == IGVM_VHT_SRAT:
                print('IGVM_VHT_SRAT(%x)' % offset, dumps(IGVM_VHS_PARAMETER.from_buffer(raw, offset + sizeof(varheader))))
            elif varheader.Type == IGVM_VHT_MADT:
                print('IGVM_VHT_MADT(%x)' % offset, dumps(IGVM_VHS_PARAMETER.from_buffer(raw, offset + sizeof(varheader))))
            elif varheader.Type == IGVM_VHT_MMIO_RANGES:
                print('IGVM_VHT_MMIO_RANGES(%x)' % offset, dumps(IGVM_VHS_MMIO_RANGES.from_buffer(raw, offset + sizeof(varheader))))
            elif varheader.Type == IGVM_VHT_SNP_ID_BLOCK:
                id_block_offset = offset
                print('IGVM_VHT_SNP_ID_BLOCK(%x)' % offset, dumps(IGVM_VHS_SNP_ID_BLOCK.from_buffer(raw, offset + sizeof(varheader))))
            elif varheader.Type == IGVM_VHT_MEMORY_MAP:
                print('IGVM_VHT_MEMORY_MAP(%x)' % offset, dumps(IGVM_VHS_PARAMETER.from_buffer(raw, offset + sizeof(varheader))))
            elif varheader.Type == IGVM_VHT_ERROR_RANGE:
                print('IGVM_VHT_ERROR_RANGE(%x)' % offset, dumps(IGVM_VHS_ERROR_RANGE.from_buffer(raw, offset + sizeof(varheader))))
            elif varheader.Type == IGVM_VHT_COMMAND_LINE:
                print('IGVM_VHT_COMMAND_LINE(%x)' % offset, dumps(IGVM_VHS_PARAMETER.from_buffer(raw, offset + sizeof(varheader))))
            elif varheader.Type == IGVM_VHT_HCL_SGX_RANGES:
                print('IGVM_VHT_HCL_SGX_RANGES(%x)' % offset)
            else:
                print('UNKNOWN(%x)' % offset)
            offset += sizeof(IGVM_VHS_VARIABLE_HEADER) + varheader.Length
            offset = (offset + 7) & ~7

    def gen_cpuid_page(self):
        cpuid_leaves = [(CpuIdFunctionExtendedSevFeatures, 0),
                        (CpuIdFunctionVendorAndMaxFunction, 0),
                        (CpuIdFunctionVersionAndFeatures, 0),
                        (CpuIdFunctionExtendedMaxFunction, 0),
                        (CpuIdFunctionCacheAndTlbInformation, 0),
                        (CpuIdFunctionMonitorMwait, 0),
                        (CpuIdFunctionPowerManagement, 0),
                        (CpuIdFunctionDirectCacheAccessParameters, 0),
                        (CpuIdFunctionPerformanceMonitoring, 0),
                        (CpuIdFunctionExtendedFeatures, 0),
                        (CpuIdFunctionCacheParameters, 0),
                        (CpuIdFunctionCacheParameters, 1),
                        (CpuIdFunctionCacheParameters, 2),
                        (CpuIdFunctionExtendedTopologyEnumeration, 0),
                        (CpuIdFunctionExtendedTopologyEnumeration, 1),
                        (CpuIdFunctionExtendedVersionAndFeatures, 0),
                        (CpuIdFunctionExtendedL1CacheParameters, 0),
                        (CpuIdFunctionExtendedL2CacheParameters, 0),
                        (CpuIdFunctionExtendedPowerManagement, 0),
                        (CpuIdFunctionExtendedAddressSpaceSizes, 0),
                        (CpuIdFunctionExtendedSvmVersionAndFeatures, 0),
                        (CpuIdFunctionProcessorTopologyDefinition, 0),
                        (CpuIdFunctionExtendedStateEnumeration, 0),
                        (CpuIdFunctionExtendedStateEnumeration, 1),
                        (CpuIdFunctionExtendedStateEnumeration, 2),
                        (CpuIdFunctionExtendedStateEnumeration, 3),
                        (CpuIdFunctionExtendedStateEnumeration, 4),
                        (CpuIdFunctionExtendedStateEnumeration, 5),
                        (CpuIdFunctionExtendedStateEnumeration, 6),
                        (CpuIdFunctionExtendedStateEnumeration, 7),
                        (CpuIdFunctionExtendedStateEnumeration, 8),
                        (CpuIdFunctionExtendedBrandingString1, 0),
                        (CpuIdFunctionExtendedBrandingString2, 0),
                        (CpuIdFunctionExtendedBrandingString3, 0),
                        (CpuIdFunctionCacheTopologyDefinition, 0),
                        (CpuIdFunctionCacheTopologyDefinition, 1),
                        (CpuIdFunctionCacheTopologyDefinition, 2),
                        (CpuIdFunctionCacheTopologyDefinition, 3)]
        cpuid_page = HV_PSP_CPUID_PAGE()
        for i in range(len(cpuid_leaves)):
            cpuid_page.Count += 1
            cpuid_page.CpuidLeafInfo[i].EaxIn = cpuid_leaves[i][0]
            cpuid_page.CpuidLeafInfo[i].EcxIn = cpuid_leaves[i][1]
            if cpuid_leaves[i][0] == CpuIdFunctionExtendedStateEnumeration:
                cpuid_page.CpuidLeafInfo[i].XfemIn = 1
        return cpuid_page

    def gen_vmsa(self):
        vmsa = SVM_VMSA()
        for (r1, r2) in [('Es', 'es'), ('Cs', 'cs'), ('Ss', 'ss'), ('Ds', 'ds'), ('Fs', 'fs'), ('Gs', 'gs'), ('Tr', 'tr')]:
            getattr(vmsa, r1).Selector = getattr(self.regs, r2).selector
            getattr(vmsa, r1).Attrib = getattr(self.regs, r2).attrib()
            getattr(vmsa, r1).Limit = getattr(self.regs, r2).limit
            getattr(vmsa, r1).Base = getattr(self.regs, r2).base
        vmsa.Gdtr.Limit = self.regs.gdtr.limit
        vmsa.Gdtr.Base = self.regs.gdtr.base
        vmsa.Idtr.Limit = self.regs.idtr.limit
        vmsa.Idtr.Base = self.regs.idtr.base
        vmsa.Efer = cast(pointer(self.regs.efer), POINTER(c_uint32)).contents.value
        vmsa.Cr4 = cast(pointer(self.regs.cr4), POINTER(c_uint32)).contents.value
        vmsa.Cr3 = self.regs.cr3.value
        vmsa.Cr0 = cast(pointer(self.regs.cr0), POINTER(c_uint32)).contents.value
        vmsa.Rflags = cast(pointer(self.regs.eflags), POINTER(c_uint32)).contents.value
        vmsa.GuestPat = 0x7040600070406
        vmsa.SevFeatures = 0x9
        vmsa.VirtualTOM = 0x0
        vmsa.Xfem = 0x1
        vmsa.Rax = self.regs.rax.value
        vmsa.Rcx = self.regs.rcx.value
        vmsa.Rdx = self.regs.rdx.value
        vmsa.Rsp = self.regs.rsp.value
        vmsa.Rbp = self.regs.rbp.value
        vmsa.Rsi = self.regs.rsi.value
        vmsa.Rdi = self.regs.rdi.value
        vmsa.R8 = self.regs.r8.value
        vmsa.R9 = self.regs.r9.value
        vmsa.R10 = self.regs.r10.value
        vmsa.R11 = self.regs.r11.value
        vmsa.R12 = self.regs.r12.value
        vmsa.R13 = self.regs.r13.value
        vmsa.R14 = self.regs.r14.value
        vmsa.R15 = self.regs.r15.value
        vmsa.Rip = self.regs.rip.value
        return vmsa

    def gen_id_block(self, digest):
        x = self.sign_key.verifying_key.pubkey.point.x()
        y = self.sign_key.verifying_key.pubkey.point.y()

        block = SNP_ID_BLOCK((c_uint8 * 48)(*digest), 
                                self.config.family_id, 
                                self.config.image_id, 
                                self.config.version, 
                                self.config.guest_svn, 
                                self.config.policy)
        r, s = self.sign_key.sign(bytearray(block), sigencode=lambda r, s, o: (r, s))
        signature = IGVM_VHS_SNP_ID_BLOCK_SIGNATURE((c_uint8 * 72)(*list(r.to_bytes(48, 'little'))),
                                                    (c_uint8 * 72)(*list(s.to_bytes(48, 'little'))))
        public_key = IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY(2, 0, (c_uint8 * 72)(*list(x.to_bytes(48, 'little'))),
                                                            (c_uint8 * 72)(*list(y.to_bytes(48, 'little'))))
        id_block = IGVM_VHS_SNP_ID_BLOCK(1, 0, (c_uint8 * 3)(), block.Ld, block.FamilyId, block.ImageId, block.Version, block.GuestSvn, 1, 0, signature, public_key)
        return id_block

    def raw(self, vmsa_page, cpuid_page, secret_page, param_page, vtl):
        headers = [IGVM_FIXED_HEADER(IGVM_MAGIC_VALUE, 1, sizeof(IGVM_FIXED_HEADER), 0, 0, 0),
                   IGVM_VHS_VARIABLE_HEADER(IGVM_VHT_SUPPORTED_PLATFORM, sizeof(IGVM_VHS_SUPPORTED_PLATFORM)),
                   IGVM_VHS_SUPPORTED_PLATFORM(1, vtl, 2, 1, 0),
                   IGVM_VHS_VARIABLE_HEADER(IGVM_VHT_SNP_POLICY, sizeof(IGVM_VHS_SNP_POLICY)),
                   IGVM_VHS_SNP_POLICY(0x3001f, 1, 0)]
        offset = sum([sizeof(s) for s in headers])
        # fill in VMSA/SECRET/PARAM page
        assert not self.is_skipped(vmsa_page)
        assert not self.is_skipped(cpuid_page)
        assert not self.is_skipped(secret_page)
        assert not self.is_skipped(param_page)
        self.memory.write(vmsa_page, bytearray(self.gen_vmsa()))
        self.memory.write(cpuid_page, bytearray(self.gen_cpuid_page()))
        self.memory.write(secret_page, b'\x00' * PGSIZE)
        self.memory.write(param_page, b'\x00' * PGSIZE)
        # Add all guest pages
        end = self.memory.allocate(0, PGSIZE)
        zero_digest = sha384(b'\x00' * PGSIZE).digest()
        curr_digest = b'\x00' * 48
        for gpa in range(0, end, PGSIZE):
            page = self.memory.read(gpa, PGSIZE)
            digest = b'\x00' * 48
            measured = False
            if gpa == vmsa_page:
                pagetype = SNP_PAGE_TYPE_VMSA
                headers.append(IGVM_VHS_VARIABLE_HEADER(IGVM_VHT_VP_CONTEXT, sizeof(IGVM_VHS_VP_CONTEXT)))
                headers.append(IGVM_VHS_VP_CONTEXT(gpa, 1, 0xffffffff, 0))
                offset += sizeof(headers[-2]) + sizeof(headers[-1])
                measured = True
            elif gpa == cpuid_page:
                pagetype = SNP_PAGE_TYPE_CPUID
                headers.append(IGVM_VHS_VARIABLE_HEADER(IGVM_VHT_PAGE_DATA, sizeof(IGVM_VHS_PAGE_DATA)))
                headers.append(IGVM_VHS_PAGE_DATA(gpa, 1, 1, 0, IGVM_VHS_PAGE_DATA_TYPE_CPUID_DATA, 0))
                offset += sizeof(headers[-2]) + sizeof(headers[-1])
            elif gpa == secret_page:
                pagetype = SNP_PAGE_TYPE_SECRETS
                headers.append(IGVM_VHS_VARIABLE_HEADER(IGVM_VHT_PAGE_DATA, sizeof(IGVM_VHS_PAGE_DATA)))
                headers.append(IGVM_VHS_PAGE_DATA(gpa, 1, 0, 0, IGVM_VHS_PAGE_DATA_TYPE_SECRETS, 0))
                offset += sizeof(headers[-2]) + sizeof(headers[-1])
            elif gpa == param_page:
                pagetype = SNP_PAGE_TYPE_UNMEASURED
                headers.append(IGVM_VHS_VARIABLE_HEADER(IGVM_VHT_PARAMETER_AREA, sizeof(IGVM_VHS_PARAMETER_AREA)))
                headers.append(IGVM_VHS_PARAMETER_AREA(PGSIZE, 0, 0))
                offset += sizeof(headers[-2]) + sizeof(headers[-1])
                headers.append(IGVM_VHS_VARIABLE_HEADER(IGVM_VHT_VP_COUNT_PARAMETER, sizeof(IGVM_VHS_PARAMETER)))
                headers.append(IGVM_VHS_PARAMETER(0, 0))
                offset += sizeof(headers[-2]) + sizeof(headers[-1])
                headers.append(IGVM_VHS_VARIABLE_HEADER(IGVM_VHT_MEMORY_MAP, sizeof(IGVM_VHS_PARAMETER)))
                headers.append(IGVM_VHS_PARAMETER(0, sizeof(IGVM_VHS_MEMORY_MAP_ENTRY)))
                offset += sizeof(headers[-2]) + sizeof(headers[-1])
                headers.append(IGVM_VHS_VARIABLE_HEADER(IGVM_VHT_PARAMETER_INSERT, sizeof(IGVM_VHS_PARAMETER_INSERT)))
                headers.append(IGVM_VHS_PARAMETER_INSERT(gpa, 1, 0))
                offset += sizeof(headers[-2]) + sizeof(headers[-1])
            elif not self.is_skipped(gpa):
                pagetype = SNP_PAGE_TYPE_NORMAL
                headers.append(IGVM_VHS_VARIABLE_HEADER(IGVM_VHT_PAGE_DATA, sizeof(IGVM_VHS_PAGE_DATA)))
                headers.append(IGVM_VHS_PAGE_DATA(gpa, 1, 1 if any(page) else 0, 0, IGVM_VHS_PAGE_DATA_TYPE_NORMAL, 0))
                offset += sizeof(headers[-2]) + sizeof(headers[-1])
                measured = True
            else:
                assert not any(page)
                continue
            if measured:
                digest = sha384(page).digest() if any(page) else zero_digest
            info = SNP_PAGE_INFO((c_uint8 * 48)(*curr_digest), (c_uint8 * 48)(*digest), sizeof(SNP_PAGE_INFO), pagetype, 0, 0, gpa)
            curr_digest = sha384(bytearray(info)).digest()
            assert offset % 8 == 0
        # Add the SNP_ID_BLOCK
        headers.append(IGVM_VHS_VARIABLE_HEADER(IGVM_VHT_SNP_ID_BLOCK, sizeof(IGVM_VHS_SNP_ID_BLOCK)))
        headers.append(self.gen_id_block(curr_digest))
        offset += sizeof(headers[-2]) + sizeof(headers[-1])
        assert offset % 8 == 0
        # Assemble the IGVM file
        body = bytearray()
        headers[0].VariableHeaderSize = offset - headers[0].VariableHeaderOffset
        for h in headers:
            if hasattr(h, 'GPA') and hasattr(h, 'FileOffset') and h.FileOffset:
                h.FileOffset = offset
                body.extend(self.memory[h.GPA:h.GPA + PGSIZE])
                offset += PGSIZE
        headers[0].TotalFileSize = offset
        return b''.join([bytearray(h) for h in headers]) + body


""" Memory Layout
|------|-------|**----|*---|***---|*******0-------0|****----|
  BIOS  RESVD  ACPI   VMSA  cpuids   vmlinux      boot_params
                            secrets               command
                            params                ramdisk
*: data imported and measured 
0: memory required used before long mode

HV should launch_update some empty pages since
1. startup_32 uses boot_stack(unrelocated) and pgtable(relocated)
2. pvalidate must run after jumping to long mode (startup_64)
See more details in arch/x86/boot/compressed/head_64.S
  |<-----------vmlinux.bin-------->|
A:|*********|*******|**************|------|0000|-------|--------------|
 start_32  start_64  compressed   heap  stack pgtable _end
  |<-------------------------------init_size ------------------------>|

B:|-------------|---------------------------------------------|0000000|
                |<-----------vmlinux.bin-------->|          pgtable  _end

startup_32 accesses boot_stack based on the original layout A;
startup_32 sets up pgtable using future layout B.
"""
BOOT_HEAP_SIZE = 0x10000
BOOT_STACK_SIZE = 0x4000
BOOT_PGT_SIZE = 0x6000
TOP_PGT_SIZE = 0x1000
INIT_PGTABLE_SIZE = TOP_PGT_SIZE + BOOT_PGT_SIZE


def load_kernel(kernel, cmdline, ramdisk, vtl, config, sign_key):
    assert type(kernel) is bytearray
    assert type(cmdline) is bytearray
    assert type(ramdisk) is bytearray
    state = IGVMFile(config, sign_key)
    state.setup_acpi()
    # VMSA page at 0x200000
    state.seek(ACPI_END_ADDR)
    vmsa_page = state.memory.allocate(PGSIZE)  # VMSA page

    # for CPUID/secrets/param pages
    state.seek(0x800000)
    cpuid_page = state.memory.allocate(PGSIZE)
    secrets_page = state.memory.allocate(PGSIZE)
    param_page = state.memory.allocate(PGSIZE)
    # Parse BzImage header
    header = setup_header.from_buffer(kernel, 0x1f1)
    assert header.header.to_bytes(
        4, 'little') == b'HdrS', 'invalid setup_header'
    assert header.pref_address > 3 * 1024 * 1024, 'loading base cannot be below 3MB'
    assert header.xloadflags & 1, '64-bit entrypoint does not exist'
    assert header.pref_address % PGSIZE == 0
    assert header.init_size % PGSIZE == 0
    # Skip setup code in real mode
    vmlinux_bin_start = (header.setup_sects + 1) * 512
    assert vmlinux_bin_start < len(kernel)
    # compressed/vmlinux at header.pref_address
    kernel_base = header.pref_address
    kernel_size = header.syssize * 0x10
    kernel_size = int((kernel_size + PGSIZE - 1) / PGSIZE) * PGSIZE
    state.seek(kernel_base)
    kernel_base = state.memory.allocate(kernel_size)
    vmlinux_bin = kernel[vmlinux_bin_start:]
    state.memory.write(kernel_base, vmlinux_bin)
    kernel_end = state.memory.allocate(0)

    # Allocate BOOT_STACK
    boot_stack_addr = kernel_end + BOOT_HEAP_SIZE
    state.seek(boot_stack_addr)
    state.memory.allocate(BOOT_STACK_SIZE)

    # Allocate pgtable
    pgtable_addr = kernel_base + header.init_size - INIT_PGTABLE_SIZE
    state.seek(pgtable_addr)
    state.memory.allocate(INIT_PGTABLE_SIZE)
    init_end = header.pref_address + header.init_size
    state.seek(init_end)

    # setup architectural env (no paging is needed for 32-bit)
    state.setup_gdt()
    # allocate boot_params, cmdline and ramdisk pages
    params_page = state.memory.allocate(sizeof(boot_params), 8)
    cmdline_page = state.memory.allocate(len(cmdline), 8)
    ramdisk_pages = state.memory.allocate(len(ramdisk), PGSIZE)
    end = state.memory.allocate(0, PGSIZE)
    # initialize boot_params
    kernel_entry = kernel_base
    params = boot_params.from_buffer(state.memory, params_page)
    params.hdr = header
    params.hdr.code32_start = kernel_base
    params.hdr.type_of_loader = 0xff
    state.memory.write(cmdline_page, cmdline)
    params.hdr.cmd_line_ptr = cmdline_page
    params.hdr.cmdline_size = len(cmdline)
    state.memory.write(ramdisk_pages, ramdisk)
    params.hdr.ramdisk_image = ramdisk_pages
    params.hdr.ramdisk_size = len(ramdisk)
    params.acpi_rsdp_addr = 0xe0000
    # give 1GB to the kernel
    params.e820_entries = 8
    params.e820_table[0].addr = 0
    params.e820_table[0].size = 0
    params.e820_table[0].type = E820_TYPE_RAM
    params.e820_table[1].addr = 0xa0000
    params.e820_table[1].size = 0x100000 - 0xa0000
    params.e820_table[1].type = E820_TYPE_RESERVED
    params.e820_table[2].addr = 0x100000
    params.e820_table[2].size = ACPI_END_ADDR - 0x100000
    params.e820_table[2].type = E820_TYPE_ACPI
    params.e820_table[3].addr = ACPI_END_ADDR
    params.e820_table[3].size = 0x100000
    params.e820_table[3].type = E820_TYPE_RESERVED
    params.e820_table[4].addr = header.pref_address
    params.e820_table[4].size = kernel_size
    params.e820_table[4].type = E820_TYPE_RAM
    params.e820_table[5].addr = boot_stack_addr
    params.e820_table[5].size = BOOT_STACK_SIZE
    params.e820_table[5].type = E820_TYPE_RAM
    params.e820_table[6].addr = pgtable_addr
    params.e820_table[6].size = INIT_PGTABLE_SIZE
    params.e820_table[6].type = E820_TYPE_RAM
    params.e820_table[7].addr = init_end
    params.e820_table[7].size = end - init_end
    params.e820_table[7].type = E820_TYPE_RAM
    del params  # kill reference to re-allow allocation
    # update initial registers
    state.regs.rip.value = kernel_entry
    state.regs.rsi.value = params_page
    return state.raw(vmsa_page, cpuid_page, secrets_page, param_page, vtl)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', type = argparse.FileType('rb'), metavar = 'igvmfile.bin', help = 'igvmfile for inspection')
    parser.add_argument('-o', type = argparse.FileType('wb'), metavar = 'igvmfile.bin', help = 'igvmfile to output')
    parser.add_argument('-kernel', type = argparse.FileType('rb'), metavar = 'bzImage')
    parser.add_argument('-append', type = str, metavar = 'cmdline')
    parser.add_argument('-rdinit', type = argparse.FileType('rb'), metavar = 'ramdisk')
    parser.add_argument('-vtl', type = int, metavar = '2', help = 'highest vtl', required = True)
    parser.add_argument('-config_file', type = str, help = 'igvm config file', required = False )
    parser.add_argument('-sign_key', type = argparse.FileType('rb'), help = 'private signing key', required = False)
    #sample key can be generated using `openssl ecparam -out ca.key -name secp384r1 -genkey`
    args = parser.parse_args()
    
    if args.config_file:
        try:
            file = open(args.config_file, 'r')
        except FileNotFoundError:
            print("Wrong config file path")
        config = TEIConfig(args.config_file)
    else:
        config = TEIConfig() #if no file is given , initialize with default config values

    if args.sign_key:
        sk_pem = args.sign_key.read()
        sign_key = SigningKey.from_pem(sk_pem, hashfunc=sha384)
    else:   #if no key is supplied , generate an ephermeral key for signing purpose
        sign_key = SigningKey.generate(curve=NIST384p, hashfunc=sha384)

    if args.d:
        IGVMFile.dump(bytearray(args.d.read()))
    elif args.o:
        assert args.kernel and args.append, '-kernel and -append is required'
        kernel = bytearray(args.kernel.read())
        ramdisk = bytearray(args.rdinit.read()) if args.rdinit else bytearray()
        cmdline = bytearray(args.append, 'ascii')
        rawbytes = load_kernel(kernel, cmdline, ramdisk, args.vtl, config, sign_key)
        args.o.write(rawbytes)
    else:
        parser.print_help()
