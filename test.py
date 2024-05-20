import sys
from tests import yara


yara.run('./modules/lib/yara_engine/rules/base/base.yar','./modules/lib/yara_engine/test')
