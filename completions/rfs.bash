# Bash completion for rfs (random-filesplitter v3.0.0)

_rfs_completions() {
    local cur prev words cword
    _init_completion || return

    local subcommands="split restore verify benchmark entropy analyze"
    local common_opts="-h --help -V --version -f --force -q --quiet --silent --json --direct"
    local split_opts="-n --parts -B --block-size -o --output"
    local restore_opts="-o --output -B --block-size"

    if [[ $cword -eq 1 ]]; then
        if [[ "$cur" == -* ]]; then
            COMPREPLY=( $(compgen -W "$common_opts -b --benchmark -e --entropy -a --analyze -v --verify" -- "$cur") )
        else
            COMPREPLY=( $(compgen -W "$subcommands" -- "$cur") )
        fi
        return 0
    fi

    local subcommand="${words[1]}"

    case "$prev" in
        -n|--parts)
            COMPREPLY=( $(compgen -W "2 3 4 5 8 16" -- "$cur") )
            return 0
            ;;
        -B|--block-size)
            COMPREPLY=( $(compgen -W "64K 256K 1M 4M 8M 16M" -- "$cur") )
            return 0
            ;;
        -o|--output|-a|--analyze)
            _filedir
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        case "$subcommand" in
            split)
                COMPREPLY=( $(compgen -W "$common_opts $split_opts" -- "$cur") )
                ;;
            restore)
                COMPREPLY=( $(compgen -W "$common_opts $restore_opts" -- "$cur") )
                ;;
            verify)
                COMPREPLY=( $(compgen -W "$common_opts -B --block-size" -- "$cur") )
                ;;
            analyze)
                COMPREPLY=( $(compgen -W "$common_opts" -- "$cur") )
                ;;
            *)
                COMPREPLY=( $(compgen -W "$common_opts $split_opts" -- "$cur") )
                ;;
        esac
        return 0
    fi

    _filedir
}

complete -F _rfs_completions rfs
