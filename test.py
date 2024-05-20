import sys
from tests import yara


yara.run('./src/lib/yara_engine/rules/base/base.yar','./src/lib/yara_engine/test')
