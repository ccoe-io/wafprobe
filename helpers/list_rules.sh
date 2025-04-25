#!/bin/bash
# Helper script to list available WAF rule modules, categories, and rules

# Determine script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Parse command line arguments
VERBOSE=""
MODULE=""

show_help() {
    echo "WAF Testing Rule Listing Utility"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -m, --modules     List available rule modules"
    echo "  -c, --categories  List available rule categories"
    echo "  -r, --rules       List available rules"
    echo "  --module MODULE   Specify module when listing rules (e.g., 'aws_rules')"
    echo "  -v, --verbose     Show detailed rule information"
    echo "  -h, --help        Display this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --modules                  # List all available modules"
    echo "  $0 --categories               # List all rule categories"
    echo "  $0 --rules                    # List all rules from all modules"
    echo "  $0 --rules --module graphql_rules  # List all GraphQL rules"
    echo "  $0 --rules --verbose          # List all rules with detailed information"
    echo ""
}

# No arguments, show help
if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

# Parse arguments
while [ "$1" != "" ]; do
    case $1 in
        -m | --modules )      
            python -m runners.multi_waf_tester --list-modules
            exit
            ;;
        -c | --categories )   
            python -m runners.multi_waf_tester --list-categories
            exit
            ;;
        -r | --rules )        
            RULES="yes"
            ;;
        --module )            
            shift
            MODULE="$1"
            ;;
        -v | --verbose )      
            VERBOSE="--verbose"
            ;;
        -h | --help )         
            show_help
            exit
            ;;
        * )                   
            echo "Unknown option: $1"
            show_help
            exit 1
    esac
    shift
done

# List rules if requested
if [ "$RULES" = "yes" ]; then
    if [ -n "$MODULE" ]; then
        python -m runners.multi_waf_tester --list-rules --module "$MODULE" $VERBOSE
    else
        python -m runners.multi_waf_tester --list-rules $VERBOSE
    fi
fi 