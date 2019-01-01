project('read_pcap', 'c')
pcap_dep = dependency('pcap')
glib_dep = dependency('glib-2.0')
libbsd_dep = dependency('libbsd-overlay')
src = ['read_pcap.c', 'link.c' , 'net.c', 'transport.c']
executable('read_pcap', src, dependencies : [pcap_dep, glib_dep, libbsd_dep])

