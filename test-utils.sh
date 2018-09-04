function in_array() {
	local needle="$1"
	shift

	for i
	do
		[[ $i == $needle ]] && return 0
	done

	return 1
}

# tests that any argument is equal to the first one
function eq() {
	in_array "$@"
}

function alleq() {
	lookfor="$1"
	shift
	for i in "$@"
	do
		[[ $i == $lookfor ]] || return 1
	done
}

# tests that all arguments are not equal to the first one
function neq() {
	! in_array "$@"
}

# tests that all arguments are greater than or equal to the first one
function ge() {
	lookfor="$1"
	shift
	for i in "$@"; do
		# not sure why this case is here
		if [[ "$i" == "" ]]
		then
			return 1
		elif [[ $i -lt $lookfor ]]
		then
			return 1
		fi
	done
}

# tests that all arguments are less than or equal to the first one
function le() {
	lookfor="$1"
	shift

	for i in "$@"
	do
		# not sure why this case is here
		if [[ "$i" == "" ]]
		then
			return 1
		elif [[ $i -gt $lookfor ]]
		then
			return 1
		fi
	done
}


