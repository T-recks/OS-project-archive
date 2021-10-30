# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(wait-diff-pid) begin
(wait-diff-pid) end
wait-diff-pid: exit(0)
EOF

pass;
