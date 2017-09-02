#include "plugin.h"

static bool cbYaraGen(int argc, char* argv[])
{
    if(argc < 2)
    {
        _plugin_logprintf("Usage: YaraGen addr\n");
        return false;
    }
    bool success;
    auto addr = DbgEval(argv[1], &success);
    if(!success)
    {
        _plugin_logprintf("Invalid expression \"%s\"...\n", argv[1]);
        return false;
    }
    DbgFunctionGet(addr, &addr, nullptr);
    BridgeCFGraphList graphList;
    if(!DbgAnalyzeFunction(addr, &graphList))
    {
        _plugin_logprintf("Failed to analyze function 0x%p...\n", addr);
        return false;
    }
    BridgeCFGraph graph = BridgeCFGraph(&graphList, true);
    std::string rule("rule ");
    char label[MAX_LABEL_SIZE];
    if(!DbgGetLabelAt(addr, SEG_DEFAULT, label))
        sprintf_s(label, "sub_%p", addr);
    rule += label;
    rule += " {\n";
    rule += "    meta:\n";
    rule += "        author = \"YaraGen\"\n";
    rule += "    strings:\n";
    for(auto & it : graph.nodes)
    {
        auto & node = it.second;
        std::vector<std::pair<unsigned char, bool>> maskedData;
        size_t unmasked = 0;
        for(auto & instr : node.instrs)
        {
            BASIC_INSTRUCTION_INFO basicinfo;
            DbgFunctions()->DisasmFast(instr.data, instr.addr, &basicinfo);
            for(int i = 0; i < basicinfo.size; i++)
            {
                DBGRELOCATIONINFO reloc;
                if(basicinfo.branch || DbgFunctions()->ModRelocationAtAddr(instr.addr + i, &reloc))
                    maskedData.push_back(std::make_pair(instr.data[i], true));
                else
                {
                    maskedData.push_back(std::make_pair(instr.data[i], false));
                    unmasked++;
                }
            }
        }
        size_t trim = 0;
        for(size_t i = 0; i < maskedData.size(); i++)
        {
            if(maskedData.at(maskedData.size() - i - 1).second)
                trim++;
            else
                break;
        }
        maskedData.resize(maskedData.size() - trim);
        if(maskedData.empty() && unmasked >= 4)
            continue;
        char text[64];
        sprintf_s(text, "        $0x%p = {", it.first);
        std::string yaraSig;
        yaraSig.reserve(maskedData.size() * 3 + 32);
        yaraSig = text;
        for(auto & b : maskedData)
        {
            if(b.second)
                yaraSig += " ??";
            else
            {
                sprintf_s(text, "%02X", b.first);
                yaraSig.push_back(' ');
                yaraSig += text;
            }
        }
        yaraSig += " }\n";
        rule += yaraSig;
    }
    rule += "    condition:\n";
    rule += "        all of them\n";
    rule += "}";
    _plugin_logputs(rule.c_str());
    return true; //Return false to indicate the command failed.
}

//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    _plugin_registercommand(pluginHandle, PLUGIN_NAME, cbYaraGen, false);
    return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here (clearing menus optional).
void pluginStop()
{
}

//Do GUI/Menu related things here.
void pluginSetup()
{
}
