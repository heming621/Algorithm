#-*- coding:utf8 -*-
import sys
import time
import ast
import pandas as pd
from sys import argv
from collections import defaultdict
from datetime import datetime, timedelta
from itertools import chain, combinations
# type = sys.getfilesystemencoding()

def eclat(prefix, items, rlt, minSup):
    while items:
        i,itids = items.pop()
        isupp = len(itids)
        if isupp >= minSup:
            prefixRcds = prefix + [i]
            # print(sorted(prefixRcds), ':', isupp)
            rlt[",".join(prefixRcds)] = isupp
            if len(prefixRcds) >= 2:
                continue             
            suffix = []
            for j, ojtids in items:
                jtids = itids & ojtids
                if len(jtids) >= minSup:
                    suffix.append((j,jtids))
            eclat(prefixRcds, sorted(suffix, key=lambda item: len(item[1]), reverse=True), rlt, minSup)

def subsets(arr):
    """ Returns non empty subsets of arr"""
    return chain(*[combinations(arr, i + 1) for i, a in enumerate(arr)])


def getConf(freqItems, rltConf, rltLift, minConf, minLift, lenTrans):
    """ 
    Conf(A->B) = Sup(A,B)/Sup(A) 
    Lift(A->B) = Conf(A->B)/Sup(B) = Sup(A,B)/(Sup(A)*Sup(B))
    """
    _freqItems = freqItems # dict((frozenset(k.split(",")), v) for k,v in freqItems.items())
    def getSup(item):
        """local function which Returns the support of an item"""
        return float(_freqItems[item])/lenTrans
    for item, count in _freqItems.items():
        if len(item) < 2:
            continue
        # print "item:%s"%item
        # for item in itemset:
        _subsets = map(frozenset, [x for x in subsets(item)])
        # print "item:%s, _subsets:%s"%(item, _subsets)
        for element in _subsets:
            remain = item.difference(element)              # element + remain = item
            if len(remain) > 0:
                confidence = getSup(item)/getSup(element)
                lift = confidence/getSup(remain)
                preCount, postCount = _freqItems[element], _freqItems[remain]
                if confidence >= minConf:
                    rltConf.append(((tuple(element), tuple(remain)), (preCount, postCount, confidence)))
                if lift >= minLift:
                    rltLift.append(((tuple(element), tuple(remain)), (preCount, postCount, lift))) 

def main():
    start = time.clock()

    ## (1) Get delay records from table delayanalyse, write into tmpfile.
    tStart, tEnd = '2017-10-04 19:00:00', '2017-10-04 20:00:00'     
    abnormal_ips = set(['xaa.ixd.xf.xag', 'xa.xge.xxxix.xxcxx', 'xa.xgg.xea.xxxxa', 'xa.xxxix.xcd.xfe', 'xa.xixtt.xxxix.ixd', 'xaa.ixg.xa.xee', 'xa.xga.xc.xae', 'xa.xtte.xxe.xdix', 'xa.dix.xad.xexx', 'xa.xgc.xx.xfx', 'xa.xxxix.xcxx.cc', 'xa.xixtt.ix.xxtt', 'xa.xff.xxxtt.xeix', 'xaa.ixg.x.xex', 'xaa.ixg.xa.cx', 'xa.xgg.xde.xett', 'xa.xxxix.xcx.xc', 'xaa.ixd.ttf.ixg', 'xa.xcg.xdd.xxxxa', 'xaa.ixg.xxx.xxad', 'xa.dix.xad.xed', 'xa.xge.ixg.xdg', 'xa.xxxxd.xcix.xxcxx'])
    abnormal_ips_var = set([])

    ## (2) Delay records --> Transactions. 
    window = 600
    fw_delayTrans = './data/delayTrans_%s_%s.csv' % (tStart.replace(' ','').replace('-','').replace(':',''), tEnd.replace(' ','').replace('-','').replace(':',''))
     
    ## (*) Configuration 
    itemTids = {}
    result_freq = defaultdict()
    result_conf, result_lift = [], []
    result_check = set()     # result_check = (high 1-freq item) + ('X' from 'X->Y')
    minSup = 0.5
    minConf = 0.8
    minLift = 1.1 
    trans = 0
    fw_freq_eclat = './data/freq_eclat.csv'

    ## (3) TID_Itemset -> Item_TIDSet. # not from transDict, but from file.
    start = time.clock()
    frData = open(fw_delayTrans, 'r')
    for line in frData:
        trans += 1
        times,ips = line.split(',')[0], ast.literal_eval(line[line.find(',')+1:])
        for item in ips:
            if item not in itemTids:
                itemTids[item] = set()
            itemTids[item].add(trans)
    frData.close()
    minSup = minSup*trans

    ## (4) Frequent itemsets generated.
    eclat([], sorted(itemTids.items(), key=lambda item: len(item[1]), reverse=True), result_freq, minSup)
    result_freq = dict((frozenset(k.split(",")), v) for k,v in result_freq.items())         # frozenset can be hashable
    getConf(result_freq, result_conf, result_lift, minConf, minLift, trans)

    ## (5) Write the results
    print("[INFO] len(result_freq):%s, len(result_conf):%s, len(result_lift):%s"%(len(result_freq), len(result_conf), len(result_lift)))
    fw_freq = open(fw_freq_eclat,'w')
    for itemset, sup in sorted(result_freq.items(), key=lambda i:len(i[0])):
        fw_freq.write("%s, sup:%s/%s\n"%(list(itemset), sup, trans))  # print(list(itemset), sup)
    for vals, confs in sorted(result_conf, key=lambda i:i[0]):
        pre, post = vals
        preCount, postCount, confidence = confs
        # print "%s => %s, conf:%s, preCnt:%s,postCnt:%s,lenTrans:%s" % (pre, post, confidence, preCount, postCount, trans)
        fw_freq.write("%s => %s, conf:%s, preCnt:%s,postCnt:%s,lenTrans:%s\n" % (pre, post, confidence, preCount, postCount, trans))
    for vals, lifts in sorted(result_lift, key=lambda i:i[0]):
        pre, post = vals
        preCount, postCount, lift = lifts
        # print "%s => %s, lift:%s, preCnt:%s,postCnt:%s,lenTrans:%s" % (pre, post, lift, preCount, postCount, trans)
        fw_freq.write("%s => %s, lift:%s, preCnt:%s,postCnt:%s,lenTrans:%s\n" % (pre, post, lift, preCount, postCount, trans))
        result_check.add(pre[0])
    # print "reuslt_freq_1:%s" % ["".join(itemset) for itemset in result_freq.keys() if len(itemset)==1]

    freq_1 = set("".join(itemset) for itemset in result_freq.keys() if len(itemset)==1)
    result_check |= freq_1
    common_ips = set(result_check).intersection(set(abnormal_ips))
    common_ips_var = set(result_check).intersection(set(abnormal_ips_var))
    print("------------------------------------------------")
    print("[INFO] result_check:%s\n" % result_check)
    print("[INFO] abnormal_ips:%s\n" % abnormal_ips)
    print("[INFO] abnormal_ips_var:%s" % abnormal_ips_var)
    print("------------------------------------------------")
    print("[INFO] The result_check && abnormal_ips:%s" % common_ips)
    print("[INFO] The result_check && abnormal_ips_var:%s" % common_ips_var)
    print("[INFO] len(result_check):%s, len(abnormal_ips):%s, len(common_ips):%s"%(len(result_check), len(abnormal_ips), len(common_ips)))
    print("[INFO] len(result_check):%s, len(abnormal_ips_var):%s, len(common_ips_var):%s"%(len(result_check), len(abnormal_ips_var), len(common_ips_var)))
    
    fw_freq.close()
    print("[INFO] Write into %s\n[INFO] Time cost in eclat algthm: %f s" % (fw_freq_eclat, time.clock()-start))

if __name__ == "__main__":
    main()

