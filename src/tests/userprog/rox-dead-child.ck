# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(rox-dead-child) begin
(rox-dead-child) open "do-nothing"
(rox-dead-child) read "do-nothing"
(rox-dead-child) try to write "do-nothing"
(rox-dead-child) end
rox-dead-child: exit(0)
EOF
pass;
