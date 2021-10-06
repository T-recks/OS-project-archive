# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(rox-simple) begin
(do-nothing) open "do-nothing"
(do-nothing) read "do-nothing"
(do-nothing) try to write "do-nothing"
(do-nothing) end
rox-simple: exit(0)
EOF
pass;
