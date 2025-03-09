_passworth () {
  # Only invoke if the cursor is at the end of the line
  if [[ $COMP_POINT == ${#COMP_LINE} ]]; then
    local vark_complete_type
    if [[ "$COMP_LINE" == *" " ]]; then
        vark_complete_type=empty
    else
        vark_complete_type=partial
    fi
    AARGVARK_COMPLETE=$vark_complete_type passworth $COMP_LINE
  fi
}
complete -C _passworth pw passworth