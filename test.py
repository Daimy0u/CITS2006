import sys
from tests import yara
from yara_engine.Engine import YaraEngine


yara.run('/Users/yusuke/Library/CloudStorage/OneDrive-TheUniversityofWesternAustralia/Units/CITS2006-DefCybersec/Project/CITS2006/yara_engine/rules/base/base.yar','/Users/yusuke/Library/CloudStorage/OneDrive-TheUniversityofWesternAustralia/Units/CITS2006-DefCybersec/Project/CITS2006/yara_engine/test',YaraEngine,'/Users/yusuke/Library/CloudStorage/OneDrive-TheUniversityofWesternAustralia/Units/CITS2006-DefCybersec/Project/CITS2006/master_log.txt')
