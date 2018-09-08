# seed128
[![Build Status](https://travis-ci.org/geeksbaek/seed128.svg?branch=master)](https://travis-ci.org/geeksbaek/seed128)
[![codecov](https://codecov.io/gh/geeksbaek/seed128/branch/master/graph/badge.svg)](https://codecov.io/gh/geeksbaek/seed128)
[![Go Report Card](https://goreportcard.com/badge/github.com/geeksbaek/seed128)](https://goreportcard.com/report/github.com/geeksbaek/seed128)
[![GoDoc](https://godoc.org/github.com/geeksbaek/seed128?status.svg)](https://godoc.org/github.com/geeksbaek/seed128)

This package is an implementation of the SEED128 algorithm with Go. The original source is [here](https://seed.kisa.or.kr/iwt/ko/bbs/EgovReferenceDetail.do?bbsId=BBSMSTR_000000000002&nttId=34&pageIndex=1&searchCnd=&searchWrd=).

# What is SEED?

SEED is a block cipher developed by the Korea Internet & Security Agency (KISA). It is used broadly throughout South Korean industry, but seldom found elsewhere. It gained popularity in Korea because 40-bit encryption was not considered strong enough, so the Korea Information Security Agency developed its own standard. However, this decision has historically limited the competition of web browsers in Korea, as no major SSL libraries or web browsers supported the SEED algorithm, requiring users to use an ActiveX control in Internet Explorer for secure web sites.

On April 1, 2015 the Ministry of Science, ICT and Future Planning (MSIP) announced its plan to remove the ActiveX dependency from at least 90 percent of the country's top 100 websites by 2017. Instead, HTML5-based technologies will be employed as they operate on many platforms, including mobile devices. Starting with the private sector, the ministry plans to expand this further to ultimately remove this dependency from public websites as well.

[Read more from Wikipedia](https://en.wikipedia.org/wiki/SEED)
