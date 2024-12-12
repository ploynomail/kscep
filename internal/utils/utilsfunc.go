package utils

func IsInArray[T comparable](arr []T, target T) bool {
	for _, v := range arr {
		if v == target {
			return true
		}
	}
	return false
}

// returns nil or []string{input} to populate pkix.Name.Subject
func SubjOrNil(input string) []string {
	if input == "" {
		return nil
	}
	return []string{input}
}
