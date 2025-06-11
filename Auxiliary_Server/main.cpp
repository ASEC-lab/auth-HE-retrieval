#include <getopt.h>
#include "cpprest/uri.h"
#include "Auxiliary_Server.h"

using namespace utility;


void printHelp(void)
{
    std::cout <<
            "--input <n>                    Number of secret values to transfer\n"
            "--read_keys_from_file          Read encryption keys from a local file instead of s3 bucket\n"
            "--enc_param_file <filename>    Read encryption params from a local file instead of defaults\n"
            "--batched                      Batched MAC\n"
            "--help                         Display this help message\n";
    exit(1);

}

// main function for Data owner
// includes argument handling and execution
int main(int argc, char* argv[])
{
    bool read_keys_from_file = false;
    int data_points_num = constants::DEFAULT_INPUT_SIZE;
    string params_file = "";
    bool batched = false;

    const char* const short_opts = "i:e:rnh";
    const option long_opts [] =
    {
            {"input", required_argument, nullptr, 'i'},
            {"enc_param_file", required_argument, nullptr, 'e'},
            {"read_keys_from_file", no_argument, nullptr, 'r'},
            {"no_mac", no_argument, nullptr, 'n'},
            {"batched", no_argument, nullptr, 'b'},
            {"help", no_argument, nullptr, 'h'},
    };

    while (true)
    {
        const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
        if (-1 == opt)
            break;

        switch(opt)
        {
        case 'i':
            data_points_num = std::stoi(optarg);
            break;

        case 'e':
            params_file = optarg;
            break;

        case 'r':
            read_keys_from_file = true;
            break;

        case 'b':
            batched = true;
            break;


        case 'h':
        case '?':
        default:
            printHelp();
            break;

        }

    }

    std::ofstream  metrics_file = utility::openMetricsFile(data_points_num, "AS_");
    metrics_file << AS_performance_metrics::getHeader() << endl;
    Auxiliary_Server Aux_Server(data_points_num, read_keys_from_file, batched, params_file, &metrics_file);
    Aux_Server.StartServer();
    metrics_file.close();

    return 0;
}
