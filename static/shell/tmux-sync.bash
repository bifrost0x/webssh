# Paste this complete block at an empty Bash prompt inside the intended tmux pane.
# It changes only this shell's prompt variables and private pane-local options.
if [[ -n ${BASH_VERSION-} && -n ${TMUX-} && -n ${TMUX_PANE-} ]] &&
   (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )) &&
   shopt -q promptvars && ! declare -F __webssh_sync_v1 >/dev/null &&
   ! [[ $(declare -p PS0 PS1 PS2 2>/dev/null) =~ declare\ -[a-zA-Z]*[rx] ]] &&
   [[ $(command tmux display-message -p '#{e|+:1,1}' 2>/dev/null) == 2 ]] &&
   command tmux show-options -pqv -t "$TMUX_PANE" @webssh_sync_v1 >/dev/null 2>&1; then
    __webssh_sync_v1() {
        local result=$?
        case "$1" in
            p|c)
                command tmux set-option -pqF -t "$TMUX_PANE" @webssh_sync_seq '#{e|+:#{@webssh_sync_seq},1}' \; \
                    set-option -pqF -t "$TMUX_PANE" @webssh_sync_v1 "$$:#{@webssh_sync_seq}:$1" >/dev/null 2>&1
                ;;
            b)
                command tmux set-option -pqF -t "$TMUX_PANE" @webssh_sync_v1 "$$:#{@webssh_sync_seq}:b" >/dev/null 2>&1
                ;;
        esac
        return "$result"
    }
    command tmux set-option -pq -t "$TMUX_PANE" @webssh_sync_seq 0
    PS1+='\[$(__webssh_sync_v1 p)\]'
    PS2+='\[$(__webssh_sync_v1 c)\]'
    PS0+='$(__webssh_sync_v1 b)'
    printf '%s\n' 'Folder sync prepared. Wait for WebSSH to detect it, then press Enter at the empty prompt.'
else
    printf '%s\n' 'Folder sync was not changed: already installed, unsupported shell, or protected prompt variables.'
fi
