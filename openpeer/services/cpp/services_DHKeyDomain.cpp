/*

 Copyright (c) 2013, SMB Phone Inc.
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 The views and conclusions contained in the software and documentation are those
 of the authors and should not be interpreted as representing official policies,
 either expressed or implied, of the FreeBSD Project.

 */

#include <openpeer/services/internal/services_DHKeyDomain.h>

#include <openpeer/services/IHelper.h>

#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>

#include <zsLib/XML.h>

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services) } }

#define OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_UNKNOWN "https://meta.openpeer.org/dh/modp/uknown"
#define OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_1024    "https://meta.openpeer.org/dh/modp/1024"
#define OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_1538    "https://meta.openpeer.org/dh/modp/1538"
#define OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_2048    "https://meta.openpeer.org/dh/modp/2048"
#define OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_3072    "https://meta.openpeer.org/dh/modp/3072"
#define OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_4096    "https://meta.openpeer.org/dh/modp/4096"
#define OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_6144    "https://meta.openpeer.org/dh/modp/6144"
#define OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_8192    "https://meta.openpeer.org/dh/modp/8192"


namespace openpeer
{
  namespace services
  {
    namespace internal
    {
      using CryptoPP::AutoSeededRandomPool;
      using CryptoPP::Integer;
      using CryptoPP::ModularExponentiation;
      using CryptoPP::ByteQueue;

      using namespace zsLib::XML;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark (helpers)
      #pragma mark

      struct DHPrecompiledValues
      {
        const char *mP;
        const char *mQ;
        const char *mG;
      };

      static DHPrecompiledValues sDHPrecompiles[] = {
        // 0 = unknown
        {NULL, NULL, NULL},

        // 1 = 1024
        {
          "B6CAF6732082AF5A55182304B6C211DC82549F4273E01855"
          "DAC955AE5672A5C507BDDEB5147EC0FA341F3673E2FD80C3"
          "558DBA64E75ADE49C812D064D6681DDF08E98A6A966451E4"
          "B079F649FE9138A62C19FAD2CC9A754D6D2FE661CA634B95"
          "DEE06F86C2FFB976A39310FEA0FFCF09D6BFDA0FF9F2BD63"
          "FA1E928CB95C2ECF",

          "5B657B39904157AD2A8C11825B6108EE412A4FA139F00C2A"
          "ED64AAD72B3952E283DEEF5A8A3F607D1A0F9B39F17EC061"
          "AAC6DD3273AD6F24E40968326B340EEF8474C5354B3228F2"
          "583CFB24FF489C53160CFD69664D3AA6B697F330E531A5CA"
          "EF7037C3617FDCBB51C9887F507FE784EB5FED07FCF95EB1"
          "FD0F49465CAE1767",

          "02"
        },

        // 2 = 1538
        {
          "9A5F5E8F6CF7CCCC3104044E4F4A9F9520740FB2A8F0AFFC"
          "EC39C7315EF507F26B59213BD3151B8A5CE0CB9756F86BC2"
          "5E6FDF307F67EE3EC27441CC50ADEEB8F280B9134D35FFC0"
          "4607091A873456AD442B8B737EC2C794D97BB3B6F562AC17"
          "B74C620F1D750FEF2B4CE3B21712E610E71C584F87599203"
          "47EAA9EB739C20202BB18D932EAD1A3FE855955AF55D17F0"
          "CE4570F29DB07AFBBE86F76D7B5D31DAB0F6760D6D37AA86"
          "2704307C089A98C1CBF5153F371E0CE37E18B12647C400B3",

          "4D2FAF47B67BE6661882022727A54FCA903A07D9547857FE"
          "761CE398AF7A83F935AC909DE98A8DC52E7065CBAB7C35E1"
          "2F37EF983FB3F71F613A20E62856F75C79405C89A69AFFE0"
          "2303848D439A2B56A215C5B9BF6163CA6CBDD9DB7AB1560B"
          "DBA631078EBA87F795A671D90B897308738E2C27C3ACC901"
          "A3F554F5B9CE101015D8C6C997568D1FF42ACAAD7AAE8BF8"
          "6722B8794ED83D7DDF437BB6BDAE98ED587B3B06B69BD543"
          "1382183E044D4C60E5FA8A9F9B8F0671BF0C589323E20059",

          "03"
        },

        // 3 = 2048
        {
          "E81724A6683F5C98638A243EA698DC03D7CE089AE426D286"
          "0D506A34FDD0F9E9FBC8285A822377553F342FDA4EE14F5B"
          "5CA5014F6B0638F5B8B3A904A639C6B7ACE6E0462770954D"
          "34AC065C115813C67152DE611FC2ED388962A9E73EF29C33"
          "E9C6D568B045F69F5D9C8582CFBA0B20DE5D25B21FB79E95"
          "F60640287BF711C6E79B7ACFC12DA9812F6073A21EC7559F"
          "C3E46B502F2BAFE28657A2676D71FB9BCA4197D45A5AE690"
          "17E1E62F4D484E1151F485DC217560342F5DA4CD9A87996A"
          "2D006595D95D9C82316A87F57E4F0A3C2465A3BC5034013A"
          "DAACEC2242BA8BED1B21141E975CA90448EF413CCEF88CF4"
          "D8BFB21630714239B6FFC58296CC0243",

          "740B9253341FAE4C31C5121F534C6E01EBE7044D72136943"
          "06A8351A7EE87CF4FDE4142D4111BBAA9F9A17ED2770A7AD"
          "AE5280A7B5831C7ADC59D482531CE35BD673702313B84AA6"
          "9A56032E08AC09E338A96F308FE1769C44B154F39F794E19"
          "F4E36AB45822FB4FAECE42C167DD05906F2E92D90FDBCF4A"
          "FB0320143DFB88E373CDBD67E096D4C097B039D10F63AACF"
          "E1F235A81795D7F1432BD133B6B8FDCDE520CBEA2D2D7348"
          "0BF0F317A6A42708A8FA42EE10BAB01A17AED266CD43CCB5"
          "168032CAECAECE4118B543FABF27851E1232D1DE281A009D"
          "6D567611215D45F68D908A0F4BAE54822477A09E677C467A"
          "6C5FD90B1838A11CDB7FE2C14B660121",

          "03"
        },

        // 4 = 3072
        {
          "B8429FE19BC51E678D050B7473535E745E125A3376490300"
          "F97A102A7547615A2DA92C7894C3FC74A66D19501FADA3DF"
          "B36C8DE9F9CAD54EE1AF716296FBACCE9844B7FA230AA114"
          "DAD48C983319115B96E4AF3534E39117E658B82D4CBDFE6F"
          "9A215C8BB69B291B452E7C96FAEF775D9F063E6199607B8B"
          "3766C355F5908E68346A75A50589F641BBDB88014001E002"
          "6FCC93AF4FC98D25712C986D66BC5875943412B85DCAB59F"
          "B496FCF4A9CE75E7B669B72895EB3599839E3F1D0AB73618"
          "C07654A90EE9EE5C90937647CFAFED689297CF9CCF010F02"
          "BADD2598A32DA14B752478D582A146883C2BD7848B2D1C6B"
          "6EF57319268CD20118C27DA01FAD39C4C4208B394AEDE0C6"
          "A28CB2D3A13F9C522ECEE7846E16FAF21DB5944FDD92119B"
          "637F2303BA8490D5E3A5B45795C022B79C2DE3C11AC90EE5"
          "393091E2C0F80F093DEFEE8D7B33F412106BC5957DB8439D"
          "BEA9502139C51B0EE383B34E11676D70CDC90FBADF8779CA"
          "A5B77344EC9A8585CF22056925C2C76EE8D5A7747E73E1D3",

          "5C214FF0CDE28F33C68285BA39A9AF3A2F092D19BB248180"
          "7CBD08153AA3B0AD16D4963C4A61FE3A53368CA80FD6D1EF"
          "D9B646F4FCE56AA770D7B8B14B7DD6674C225BFD1185508A"
          "6D6A464C198C88ADCB72579A9A71C88BF32C5C16A65EFF37"
          "CD10AE45DB4D948DA2973E4B7D77BBAECF831F30CCB03DC5"
          "9BB361AAFAC847341A353AD282C4FB20DDEDC400A000F001"
          "37E649D7A7E4C692B8964C36B35E2C3ACA1A095C2EE55ACF"
          "DA4B7E7A54E73AF3DB34DB944AF59ACCC1CF1F8E855B9B0C"
          "603B2A548774F72E4849BB23E7D7F6B4494BE7CE67808781"
          "5D6E92CC5196D0A5BA923C6AC150A3441E15EBC245968E35"
          "B77AB98C934669008C613ED00FD69CE26210459CA576F063"
          "51465969D09FCE29176773C2370B7D790EDACA27EEC908CD"
          "B1BF9181DD42486AF1D2DA2BCAE0115BCE16F1E08D648772"
          "9C9848F1607C07849EF7F746BD99FA090835E2CABEDC21CE"
          "DF54A8109CE28D8771C1D9A708B3B6B866E487DD6FC3BCE5"
          "52DBB9A2764D42C2E79102B492E163B7746AD3BA3F39F0E9",

          "03"
        },

        // 5 = 4096
        {
          "C35D11CEC8070891839277F96F9D94BB4C72993B198016E9"
          "3A4AC49B12F0467B918677BA30D13FA60876C48804A529AA"
          "B44233344AF70425556A7E1139A5C976C38AD084FA9DF6A4"
          "0FA1EA011D59A719D37DFBA0440AE76CEC7A762BD9B61AEB"
          "F598C4002D38166FF5B06717B15CDF8CF6115E623625EEAB"
          "28AE8A973573379F60927E791A6E3532BF6AEA831F175992"
          "87A3A382844F3343AEFA8C1E7FF529813872B093B0E6586C"
          "73FA32DB5709B12A3EE0953EAA5360E5470807C164594801"
          "9FBDFBB371B3670F6708474570C9E7CC916BD7C12E40546E"
          "97DE33715C2EAE3409C7DD7FBEB8519C88E2CC315019A00B"
          "8B4FEB6F876A771F2FEEBBC2E7C19C61BD9B8EBF372FC1BC"
          "341C24ACD6F0C9386238AED9069177F5732B29CA5F279E9A"
          "90B9CC9D54992EF488653918E537A941D0A104FC9FA1ABEA"
          "56157930033CDF1CFFD128E86471518F1AAA773862A44564"
          "C4B6DB4D2CF839AFF8578656A7805C68206A242A963F1209"
          "446D581DA6BF948259E60BCF3A394C0285C633892741A1E1"
          "DC81C35B38CADBF4720FFBB7E1A2153F210A18771AC43170"
          "AA49DC7104C5E1FFFFB279516C98F39F8056DB2B80666B3B"
          "1AF2D84D6BB95DB8F36F2B92DD27E9E3B1BDB2C48B2EACE1"
          "D3D7ABD8EB2BA81C48142A4EC764E3427760330F3AC271E8"
          "8B157201D185B0DA13925F6AF5AB6CA3141BAFE9A8460A13"
          "FFAE77AD2629480F",

          "61AE88E764038448C1C93BFCB7CECA5DA6394C9D8CC00B74"
          "9D25624D8978233DC8C33BDD18689FD3043B6244025294D5"
          "5A21199A257B8212AAB53F089CD2E4BB61C568427D4EFB52"
          "07D0F5008EACD38CE9BEFDD0220573B6763D3B15ECDB0D75"
          "FACC6200169C0B37FAD8338BD8AE6FC67B08AF311B12F755"
          "9457454B9AB99BCFB0493F3C8D371A995FB575418F8BACC9"
          "43D1D1C1422799A1D77D460F3FFA94C09C395849D8732C36"
          "39FD196DAB84D8951F704A9F5529B072A38403E0B22CA400"
          "CFDEFDD9B8D9B387B38423A2B864F3E648B5EBE097202A37"
          "4BEF19B8AE17571A04E3EEBFDF5C28CE44716618A80CD005"
          "C5A7F5B7C3B53B8F97F75DE173E0CE30DECDC75F9B97E0DE"
          "1A0E12566B78649C311C576C8348BBFAB99594E52F93CF4D"
          "485CE64EAA4C977A44329C8C729BD4A0E850827E4FD0D5F5"
          "2B0ABC98019E6F8E7FE894743238A8C78D553B9C315222B2"
          "625B6DA6967C1CD7FC2BC32B53C02E34103512154B1F8904"
          "A236AC0ED35FCA412CF305E79D1CA60142E319C493A0D0F0"
          "EE40E1AD9C656DFA3907FDDBF0D10A9F90850C3B8D6218B8"
          "5524EE388262F0FFFFD93CA8B64C79CFC02B6D95C033359D"
          "8D796C26B5DCAEDC79B795C96E93F4F1D8DED96245975670"
          "E9EBD5EC7595D40E240A152763B271A13BB019879D6138F4"
          "458AB900E8C2D86D09C92FB57AD5B6518A0DD7F4D4230509"
          "FFD73BD69314A407",

          "02"
        },

        // 6 = 6144
        {
          "A36434E66E419F3BFBBBEB1B1E19C4F33A95B7BC436195EF"
          "01B04EFB48468421ADDE224DCD9AC862C2304471B32FEA9E"
          "B86AC936A4E33034C6680302713212A1075CA95278C4E9D4"
          "9C3633AF87C0E7A8C7DD4476A0CFD3B9CECD02FF8604D858"
          "FBB4723596364A63FEA9BA9F7EB7D703CD4B03E92944177F"
          "4AE48AF50D76F2D75412866D884B3E589497A782380C4688"
          "137DBCEC58BDFA6FD79E426DF8BE0AC46C87DBE3D88D3812"
          "F6693CD273A7945B843CFFBA2DDF5D7E1242CA96D0175C99"
          "2BB8B72047DF955C83F57336433BCD0F8BABE3D7366760F7"
          "4BE32EC8D4FC92684CA6705522BE6153460910FB58B7B17C"
          "805B31051F1352ADB081381E645AF824D6547F03824B9027"
          "1B7CED5205DE3361761272F04F71BAD3858DCF145B96DC59"
          "0223CE318A211785F35219D0F43760A7FFCA5FF4C26D1423"
          "0EA0883A571908AEE491CB4DAB3D234339F84F8124374EEE"
          "EEF5081278E1DB90208A266C8C529A54766CE5B3562F05A5"
          "FFC618EB0000B04FDA6291BFC57104EAE64AB1350F157C84"
          "D0F8D24023B857E22B784B53AEF2E502B39362924E644553"
          "68CE0479DA26956BF31DC61B9CD0279F7116DCD5C3CEE6AA"
          "2E9FB56C4635517E58DE5E39114A51AA107B84B825A69477"
          "781B27EC2C4E069B7CD1108C69186CA1C6F012C0963C1A3A"
          "7F87F81C83D2AC8B3B8106EF5998C319B96EAD1B2CC61C4F"
          "19DC774F97F06015E185A2C3812F4FB10AC3FC113A699C95"
          "69533B98CDEB398BD791CA2237ACADD27C32A5C088C26298"
          "DCCD62F79976FE9C7BC4535CB01201B9AB422B6E27EFD66F"
          "AEFD2262452FE0BF318B7B94118B697053B72BC78283C47B"
          "DE1B1638607B25D7B668721E1BE49B65D5459433709B5E77"
          "846EF1B2E33FC5871899E8EB5A95939B31A5D4356D78F0B8"
          "0C0D29BA939E92646BEEA020F4952051C080C2885697FB18"
          "41C36E1AD0124F14CCA34A92C9124F08048D6D237BC6EFE4"
          "B1D4849774DF25A049D9A63C8248A4712F166F6159E05554"
          "E62FAEF95E06005EEF3EB3B7F3BC074CFE727746A5CB6EBB"
          "DD46A17FB3723E62B9B56D0D9AFB63DA1D22C40E7EF1332B",

          "51B21A733720CF9DFDDDF58D8F0CE2799D4ADBDE21B0CAF7"
          "80D8277DA4234210D6EF1126E6CD643161182238D997F54F"
          "5C35649B5271981A633401813899095083AE54A93C6274EA"
          "4E1B19D7C3E073D463EEA23B5067E9DCE766817FC3026C2C"
          "7DDA391ACB1B2531FF54DD4FBF5BEB81E6A581F494A20BBF"
          "A572457A86BB796BAA094336C4259F2C4A4BD3C11C062344"
          "09BEDE762C5EFD37EBCF2136FC5F05623643EDF1EC469C09"
          "7B349E6939D3CA2DC21E7FDD16EFAEBF0921654B680BAE4C"
          "95DC5B9023EFCAAE41FAB99B219DE687C5D5F1EB9B33B07B"
          "A5F197646A7E49342653382A915F30A9A304887DAC5BD8BE"
          "402D98828F89A956D8409C0F322D7C126B2A3F81C125C813"
          "8DBE76A902EF19B0BB09397827B8DD69C2C6E78A2DCB6E2C"
          "8111E718C5108BC2F9A90CE87A1BB053FFE52FFA61368A11"
          "8750441D2B8C84577248E5A6D59E91A19CFC27C0921BA777"
          "777A84093C70EDC81045133646294D2A3B3672D9AB1782D2"
          "FFE30C7580005827ED3148DFE2B882757325589A878ABE42"
          "687C692011DC2BF115BC25A9D779728159C9B149273222A9"
          "B467023CED134AB5F98EE30DCE6813CFB88B6E6AE1E77355"
          "174FDAB6231AA8BF2C6F2F1C88A528D5083DC25C12D34A3B"
          "BC0D93F61627034DBE688846348C3650E37809604B1E0D1D"
          "3FC3FC0E41E956459DC08377ACCC618CDCB7568D96630E27"
          "8CEE3BA7CBF8300AF0C2D161C097A7D88561FE089D34CE4A"
          "B4A99DCC66F59CC5EBC8E5111BD656E93E1952E04461314C"
          "6E66B17BCCBB7F4E3DE229AE580900DCD5A115B713F7EB37"
          "D77E91312297F05F98C5BDCA08C5B4B829DB95E3C141E23D"
          "EF0D8B1C303D92EBDB34390F0DF24DB2EAA2CA19B84DAF3B"
          "C23778D9719FE2C38C4CF475AD4AC9CD98D2EA1AB6BC785C"
          "060694DD49CF493235F750107A4A9028E04061442B4BFD8C"
          "20E1B70D6809278A6651A549648927840246B691BDE377F2"
          "58EA424BBA6F92D024ECD31E41245238978B37B0ACF02AAA"
          "7317D77CAF03002F779F59DBF9DE03A67F393BA352E5B75D"
          "EEA350BFD9B91F315CDAB686CD7DB1ED0E9162073F789995",
          "03"
        },

        // 7 = 8192
        {
          NULL, //"",
          NULL, //"",
          NULL, //""
        }
      };

      //-------------------------------------------------------------------------
      static size_t toIndex(IDHKeyDomain::KeyDomainPrecompiledTypes length)
      {
        switch (length) {
          case IDHKeyDomain::KeyDomainPrecompiledType_Unknown:  return 0;
          case IDHKeyDomain::KeyDomainPrecompiledType_1024:     return 1;
          case IDHKeyDomain::KeyDomainPrecompiledType_1538:     return 2;
          case IDHKeyDomain::KeyDomainPrecompiledType_2048:     return 3;
          case IDHKeyDomain::KeyDomainPrecompiledType_3072:     return 4;
          case IDHKeyDomain::KeyDomainPrecompiledType_4096:     return 5;
          case IDHKeyDomain::KeyDomainPrecompiledType_6144:     return 6;
          case IDHKeyDomain::KeyDomainPrecompiledType_8192:     return 7;
        }
        return 0;
      }

      //-------------------------------------------------------------------------
      static IDHKeyDomain::KeyDomainPrecompiledTypes fromIndex(size_t index)
      {
        switch (index) {
          case 0: return IDHKeyDomain::KeyDomainPrecompiledType_Unknown;
          case 1: return IDHKeyDomain::KeyDomainPrecompiledType_1024;
          case 2: return IDHKeyDomain::KeyDomainPrecompiledType_1538;
          case 3: return IDHKeyDomain::KeyDomainPrecompiledType_2048;
          case 4: return IDHKeyDomain::KeyDomainPrecompiledType_3072;
          case 5: return IDHKeyDomain::KeyDomainPrecompiledType_4096;
          case 6: return IDHKeyDomain::KeyDomainPrecompiledType_6144;
          case 7: return IDHKeyDomain::KeyDomainPrecompiledType_8192;
        }
        return IDHKeyDomain::KeyDomainPrecompiledType_Unknown;
      }

      //-----------------------------------------------------------------------
      static Log::Params slog(const char *message)
      {
        return Log::Params(message, "stack::DHKeyDomain");
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DHKeyDomain
      #pragma mark

      //-----------------------------------------------------------------------
      DHKeyDomain::DHKeyDomain()
      {
        ZS_LOG_DEBUG(log("created"))
      }

      //-----------------------------------------------------------------------
      DHKeyDomain::~DHKeyDomain()
      {
        if(isNoop()) return;
        
        ZS_LOG_DEBUG(log("destroyed"))
      }

      //-----------------------------------------------------------------------
      DHKeyDomainPtr DHKeyDomain::convert(IDHKeyDomainPtr publicKey)
      {
        return dynamic_pointer_cast<DHKeyDomain>(publicKey);
      }

      //-----------------------------------------------------------------------
      DHKeyDomainPtr DHKeyDomain::convert(ForDHPrivateKeyPtr object)
      {
        return dynamic_pointer_cast<DHKeyDomain>(object);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DHKeyDomain => IDHKeyDomain
      #pragma mark

      //-----------------------------------------------------------------------
      ElementPtr DHKeyDomain::toDebug(IDHKeyDomainPtr keyDomain)
      {
        if (!keyDomain) return ElementPtr();
        return convert(keyDomain)->toDebug();
      }

      //-----------------------------------------------------------------------
      DHKeyDomainPtr DHKeyDomain::generate(size_t keySizeInBits)
      {
        DHKeyDomainPtr pThis(new DHKeyDomain);

        AutoSeededRandomPool rnd;
        pThis->mDH.AccessGroupParameters().GenerateRandomWithKeySize(rnd, static_cast<unsigned int>(keySizeInBits));
        ZS_THROW_UNEXPECTED_ERROR_IF(!pThis->validate())  // why would we generate something that doesn't pass??

        ZS_LOG_DEBUG(pThis->debug("generated key domain"))

        return pThis;
      }

      //-----------------------------------------------------------------------
      DHKeyDomainPtr DHKeyDomain::loadPrecompiled(
                                                  KeyDomainPrecompiledTypes precompiledKey,
                                                  bool validate
                                                  )
      {
        size_t index = toIndex(precompiledKey);
        const char *pStr = sDHPrecompiles[index].mP;
        const char *qStr = sDHPrecompiles[index].mQ;
        const char *gStr = sDHPrecompiles[index].mG;

        if ((!pStr) || (!qStr) || (!gStr)) {
          ZS_LOG_ERROR(Detail, slog("precompiled key is not valid") + ZS_PARAM("length", precompiledKey))
          return DHKeyDomainPtr();
        }

        Integer p((String("0x") + pStr).c_str());
        Integer q((String("0x") + qStr).c_str());
        Integer g((String("0x") + gStr).c_str());

        SecureByteBlock resultP(p.MinEncodedSize());
        SecureByteBlock resultQ(q.MinEncodedSize());
        SecureByteBlock resultG(g.MinEncodedSize());

        p.Encode(resultP, resultP.SizeInBytes());
        q.Encode(resultQ, resultQ.SizeInBytes());
        g.Encode(resultG, resultG.SizeInBytes());

        DHKeyDomainPtr pThis = load(resultP, resultQ, resultG, validate);
        ZS_THROW_BAD_STATE_IF(!pThis) // this can't fail

        ZS_LOG_DEBUG(pThis->log("loading predefined key domain") + ZS_PARAM("length", precompiledKey) + ZS_PARAM("p", pStr) + ZS_PARAM("q", qStr) + ZS_PARAM("g", gStr))

        return pThis;
      }

      //-----------------------------------------------------------------------
      IDHKeyDomain::KeyDomainPrecompiledTypes DHKeyDomain::getPrecompiledType() const
      {
        SecureByteBlock p;
        SecureByteBlock q;
        SecureByteBlock g;

        save(p, q, g);

        String pStr = IHelper::convertToHex(p, true);
        String qStr = IHelper::convertToHex(q, true);
        String gStr = IHelper::convertToHex(g, true);

        for (size_t index = 0; true; ++index)
        {
          KeyDomainPrecompiledTypes type = fromIndex(index);

          const char *pCompare = sDHPrecompiles[index].mP;
          const char *qCompare = sDHPrecompiles[index].mQ;
          const char *gCompare = sDHPrecompiles[index].mG;

          if ((pCompare) &&
              (qCompare) &&
              (gCompare)) {

            if (pStr != pCompare) continue;
            if (qStr != qCompare) continue;
            if (gStr != gCompare) continue;

            ZS_LOG_TRACE(log("found match to precompiled key") + ZS_PARAM("precompiled key", toNamespace(type)))

            return type;
          }

          if (KeyDomainPrecompiledType_Last == type) {
            break;
          }
        }

        ZS_LOG_TRACE(log("did not find match to any precompiled key"))
        return KeyDomainPrecompiledType_Unknown;
      }

      //-----------------------------------------------------------------------
      DHKeyDomainPtr DHKeyDomain::load(
                                       const SecureByteBlock &inP,
                                       const SecureByteBlock &inQ,
                                       const SecureByteBlock &inG,
                                       bool validate
                                       )
      {
        DHKeyDomainPtr pThis(new DHKeyDomain);

        try {
          Integer p(inP, inP.SizeInBytes());
          Integer q(inQ, inQ.SizeInBytes());
          Integer g(inG, inG.SizeInBytes());

          pThis->mDH.AccessGroupParameters().Initialize(p, q, g);

          if (validate) {
            if (!pThis->validate()) {
              ZS_LOG_ERROR(Debug, pThis->log("failed to load key domain") + ZS_PARAM("p", IHelper::convertToHex(inP, true)) + ZS_PARAM("q", IHelper::convertToHex(inQ, true)) + ZS_PARAM("g", IHelper::convertToHex(inG, true)))
              return DHKeyDomainPtr();
            }
          }
        } catch (CryptoPP::Exception &e) {
          ZS_LOG_ERROR(Basic, pThis->log("cryptography library threw an exception") + ZS_PARAM("what", e.what()))
          return DHKeyDomainPtr();
        }

        ZS_LOG_DEBUG(pThis->debug("loaded key domain"))

        return pThis;
      }

      //-----------------------------------------------------------------------
      void DHKeyDomain::save(
                             SecureByteBlock &outP,
                             SecureByteBlock &outQ,
                             SecureByteBlock &outG
                             ) const
      {
        Integer p = mDH.GetGroupParameters().GetModulus();
        Integer q = mDH.GetGroupParameters().GetSubgroupOrder();
        Integer g = mDH.GetGroupParameters().GetGenerator();

        outP.CleanNew(p.MinEncodedSize());
        outQ.CleanNew(q.MinEncodedSize());
        outG.CleanNew(g.MinEncodedSize());

        p.Encode(outP, outP.SizeInBytes());
        q.Encode(outQ, outQ.SizeInBytes());
        g.Encode(outG, outG.SizeInBytes());

        ZS_LOG_TRACE(debug("save called"))
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DHKeyDomain => IDHKeyDomainForDHPrivateKey
      #pragma mark

      //-----------------------------------------------------------------------
      DHKeyDomain::DH &DHKeyDomain::getDH() const
      {
        return mDH;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DHKeyDomain => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params DHKeyDomain::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("stack::DHKeyDomain");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params DHKeyDomain::debug(const char *message) const
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      ElementPtr DHKeyDomain::toDebug() const
      {
        ElementPtr resultEl = Element::create("stack::DHKeyDomain");

        Integer p = mDH.GetGroupParameters().GetModulus();
        Integer q = mDH.GetGroupParameters().GetSubgroupOrder();
        Integer g = mDH.GetGroupParameters().GetGenerator();

        SecureByteBlock outP(p.MinEncodedSize());
        SecureByteBlock outQ(q.MinEncodedSize());
        SecureByteBlock outG(g.MinEncodedSize());

        p.Encode(outP, outP.SizeInBytes());
        q.Encode(outQ, outQ.SizeInBytes());
        g.Encode(outG, outG.SizeInBytes());

        IHelper::debugAppend(resultEl, "id", mID);
        IHelper::debugAppend(resultEl, "p", IHelper::convertToHex(outP, true));
        IHelper::debugAppend(resultEl, "q", IHelper::convertToHex(outQ, true));
        IHelper::debugAppend(resultEl, "g", IHelper::convertToHex(outG, true));

        IHelper::debugAppend(resultEl, "p bit-count", p.BitCount());
        IHelper::debugAppend(resultEl, "q bit-count", q.BitCount());
        IHelper::debugAppend(resultEl, "g bit-count", g.BitCount());

        return resultEl;
      }

      //-----------------------------------------------------------------------
      bool DHKeyDomain::validate() const
      {
        ZS_LOG_DEBUG(log("validating key domain"))

        try {
          AutoSeededRandomPool rnd;

          if(!mDH.GetGroupParameters().ValidateGroup(rnd, 3)) {
            ZS_LOG_ERROR(Detail, log("failed to validate key domain"))
            return false;
          }

          Integer p = mDH.GetGroupParameters().GetModulus();
          Integer q = mDH.GetGroupParameters().GetSubgroupOrder();
          Integer g = mDH.GetGroupParameters().GetGenerator();

          Integer v = ModularExponentiation(g, q, p);
          if(v != Integer::One()) {
            ZS_LOG_ERROR(Detail, log("failed to verify order of the subgroup"))
          }
        } catch (CryptoPP::Exception &e) {
          ZS_LOG_ERROR(Basic, log("cryptography library threw an exception") + ZS_PARAM("what", e.what()))
          return false;
        }

        return true;
      }

    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IDHKeyDomain
    #pragma mark

    //-------------------------------------------------------------------------
    const char *IDHKeyDomain::toNamespace(KeyDomainPrecompiledTypes length)
    {
      switch (length) {
        case KeyDomainPrecompiledType_Unknown:  return OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_UNKNOWN;
        case KeyDomainPrecompiledType_1024:     return OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_1024;
        case KeyDomainPrecompiledType_1538:     return OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_1538;
        case KeyDomainPrecompiledType_2048:     return OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_2048;
        case KeyDomainPrecompiledType_3072:     return OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_3072;
        case KeyDomainPrecompiledType_4096:     return OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_4096;
        case KeyDomainPrecompiledType_6144:     return OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_6144;
        case KeyDomainPrecompiledType_8192:     return OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_8192;
      }
      return OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_UNKNOWN;
    }

    //-------------------------------------------------------------------------
    IDHKeyDomain::KeyDomainPrecompiledTypes IDHKeyDomain::fromNamespace(const char *inNamespace)
    {
      if (!inNamespace) return KeyDomainPrecompiledType_Unknown;
      if ('\0' == *inNamespace) return KeyDomainPrecompiledType_Unknown;

      if (0 == strcmp(inNamespace, OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_1024)) {
        return KeyDomainPrecompiledType_1024;
      }
      if (0 == strcmp(inNamespace, OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_1538)) {
        return KeyDomainPrecompiledType_1538;
      }
      if (0 == strcmp(inNamespace, OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_2048)) {
        return KeyDomainPrecompiledType_2048;
      }
      if (0 == strcmp(inNamespace, OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_3072)) {
        return KeyDomainPrecompiledType_3072;
      }
      if (0 == strcmp(inNamespace, OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_4096)) {
        return KeyDomainPrecompiledType_4096;
      }
      if (0 == strcmp(inNamespace, OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_6144)) {
        return KeyDomainPrecompiledType_6144;
      }
      if (0 == strcmp(inNamespace, OPENPEER_SERVICES_DH_KEY_DOMAIN_NAMESPACE_8192)) {
        return KeyDomainPrecompiledType_8192;
      }

      return KeyDomainPrecompiledType_Unknown;
    }

    //-------------------------------------------------------------------------
    ElementPtr IDHKeyDomain::toDebug(IDHKeyDomainPtr keyDomain)
    {
      return internal::DHKeyDomain::toDebug(keyDomain);
    }

    //-------------------------------------------------------------------------
    IDHKeyDomainPtr IDHKeyDomain::generate(size_t keySizeInBits)
    {
      return internal::IDHKeyDomainFactory::singleton().generate(keySizeInBits);
    }

    //-------------------------------------------------------------------------
    IDHKeyDomainPtr IDHKeyDomain::loadPrecompiled(
                                                  KeyDomainPrecompiledTypes precompiledKey,
                                                  bool validate
                                                  )
    {
      return internal::IDHKeyDomainFactory::singleton().loadPrecompiled(precompiledKey, validate);
    }

    //-------------------------------------------------------------------------
    IDHKeyDomainPtr IDHKeyDomain::load(
                                       const SecureByteBlock &p,
                                       const SecureByteBlock &q,
                                       const SecureByteBlock &g,
                                       bool validate
                                       )
    {
      return internal::IDHKeyDomainFactory::singleton().load(p, q, g, validate);
    }

  }
}
