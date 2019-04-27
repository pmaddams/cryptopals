package main

import (
	"testing"
	"time"
)

func TestUint32(t *testing.T) {
	nums := []uint32{
		3521569528,
		1101990581,
		1076301704,
		2948418163,
		3792022443,
		2697495705,
		2002445460,
		502890592,
		3431775349,
		1040222146,
		3582980688,
		1840389745,
		4282906414,
		1327318762,
		2089338664,
		4131459930,
		3027134324,
		2835148530,
		1179416782,
		1849001581,
		526320344,
		2422121673,
		2517840959,
		2221714477,
		55000521,
		591044015,
		1168297933,
		1971159042,
		4039967188,
		4139787488,
		122076017,
		2865003221,
		2757324559,
		1140549535,
		244059003,
		4193854726,
		18931592,
		4249850126,
		312057759,
		3675685089,
		280972886,
		1066277295,
		2046947247,
		2429544615,
		2740628128,
		2155829340,
		3777224149,
		1593303098,
		3225103480,
		1218072373,
		721749912,
		3875531970,
		800882885,
		982222970,
		764628465,
		1297523938,
		1339440492,
		2851444106,
		2470351666,
		3514079573,
		230610872,
		3277181233,
		2300098883,
		3807585278,
		3578508239,
		585251520,
		1232810633,
		3943696428,
		2424229202,
		4056955950,
		2946778364,
		2827154017,
		3581623447,
		1646791240,
		1641222099,
		984024840,
		1406770355,
		2596261903,
		1495556502,
		3270855102,
		1365682896,
		3209664996,
		1879158171,
		3300120153,
		2153622952,
		3729021385,
		687831792,
		2006786944,
		3431925646,
		1962505324,
		2824505801,
		1348723856,
		922631220,
		3964570281,
		2769770206,
		828731557,
		4248452699,
		2959523438,
		906083865,
		1323668227,
		2159879902,
		319455449,
		3297174891,
		3705574895,
		3714968449,
		2390041620,
		2437916745,
		4154685053,
		3965519566,
		1428553812,
		2997936417,
		3678465944,
		2297665998,
		2815058381,
		3417694686,
		1347985720,
		615845907,
		349125976,
		1019565827,
		3347851281,
		3981533674,
		3297729024,
		3925636506,
		355619688,
		4268484254,
		2640476081,
		3324807233,
		1551140204,
		841631285,
		1968951868,
		2365743227,
		4096064199,
		3077311258,
		3259301778,
		2378981759,
		1934598820,
		3584520577,
		36108367,
		1581050761,
		1093529117,
		1874730399,
		1685597106,
		2597726179,
		2266304915,
		2223925333,
		3771369693,
		2802253988,
		2690882466,
		1057184506,
		2420032185,
		1649867505,
		2257883890,
		2988007661,
		1528748142,
		445279673,
		2781572616,
		2547589125,
		1488397138,
		2939049329,
		2209678138,
		2919906346,
		1244424685,
		560937141,
		1602534944,
		316121103,
		1542557076,
		924109349,
		2961813479,
		2008471243,
		457373756,
		2080742566,
		4040709882,
		2241230277,
		3443499664,
		2882722707,
		3654252370,
		2523569214,
		2082411503,
		4174049749,
		152918947,
		3412352218,
		2563927321,
		2152584714,
		3250469582,
		2110646534,
		688482869,
		2526902140,
		235242159,
		770403967,
		133158535,
		3734466538,
		3383546169,
		3940430161,
		907306493,
		4048278587,
		232906813,
		3446102344,
		3243296519,
		3497478135,
		1523495320,
		4206232155,
		2211854363,
		2646114256,
		3548837134,
		2073524170,
		3360818158,
		826307188,
		3337545539,
		4093110721,
		3501127907,
		580328410,
		756332760,
		3550166874,
		2238046283,
		1029291068,
		2064687079,
		3474577605,
		3901047683,
		3642105289,
		1398811868,
		621484999,
		4218008046,
		2813183094,
		543853333,
		519642234,
		2153111962,
		3050174117,
		1637060005,
		3999111097,
		1758941234,
		1969388945,
		1804246345,
		3656717516,
		1830932416,
		3282395084,
		1615029332,
		857696477,
		1720103836,
		3441375895,
		330231576,
		3336001336,
		1786655150,
		1113710648,
		1559913459,
		1017529512,
		3955184036,
		2469685514,
		3630483342,
		1076488855,
		3866870112,
		4083348296,
		1608661615,
		1513947641,
		807806028,
		131348723,
		3234550333,
		936836126,
		3277578587,
		3792347031,
		4203617477,
		2266672922,
		1262966978,
		2801151938,
		2390045589,
		1278793059,
		3669879059,
		3522185934,
		2321383482,
		2688990268,
		321590119,
		1661462671,
		580505929,
		1736765468,
		3105502400,
		1643215371,
		2722517626,
		4211711452,
		4227968287,
		4025175013,
		3329017232,
		2829049580,
		2746510526,
		4063979278,
		770269047,
		998736954,
		3491337543,
		3013025007,
		1890686678,
		949466602,
		735778247,
		1866640589,
		3160842605,
		906398014,
		757271116,
		2263818242,
		518120165,
		1561326779,
		1373795228,
		2143978774,
		1901466945,
		2868026183,
		3417853337,
		3849646589,
		686472202,
		3788102173,
		4225017023,
		3021583182,
		4149940292,
		2511287796,
		3597953843,
		3657493397,
		3701898245,
		1323037313,
		3879346560,
		627705343,
		3488864001,
		1725496291,
		342117436,
		2190526554,
		79473220,
		519389890,
		4008670856,
		1016397048,
		819498557,
		1570857085,
		594486484,
		210406981,
		3639306821,
		2134915414,
		149075541,
		2973040091,
		2653162267,
		2176286793,
		4091604612,
		220796846,
		2439294180,
		1957719198,
		1564518693,
		745952227,
		299668305,
		117942541,
		3028149644,
		888104451,
		987083521,
		2227983515,
		342684932,
		2806093125,
		3776255328,
		2598054445,
		2439984965,
		1126602975,
		2943866169,
		351655985,
		2745889776,
		603005469,
		860623809,
		1814993857,
		4128630736,
		440705265,
		2093957219,
		2813762326,
		3288255569,
		3621926504,
		456287235,
		2177414114,
		2934036364,
		3591118648,
		2485609281,
		2222453270,
		2347700863,
		1734163198,
		3868140140,
		2153598513,
		1018725182,
		3345738502,
		573981603,
		1015716135,
		3782909322,
		3334553752,
		3576859944,
		2248655220,
		900105388,
		684318376,
		4262603263,
		1775969570,
		3213080976,
		3011497579,
		847220656,
		3563331916,
		1838312427,
		545520348,
		1838162418,
		989058179,
		3034744981,
		363167973,
		441529580,
		346679673,
		883722578,
		2350802882,
		1145048767,
		4126145508,
		1210235779,
		3968269590,
		1161828477,
		4189186476,
		928265470,
		1045611330,
		2001923676,
		3369057642,
		1172455983,
		3249812019,
		155568810,
		4236501164,
		951632317,
		2703793783,
		2610351432,
		3393281212,
		2376823349,
		506348902,
		171498896,
		3222244595,
		734895377,
		1332960617,
		1902441257,
		4212225318,
		3770429923,
		286124923,
		1142807988,
		3095972351,
		437182228,
		1018455628,
		3473381965,
		2638101686,
		1480694747,
		3916619196,
		3500743772,
		2975252296,
		3361945483,
		3724678827,
		1899603736,
		2327632267,
		1887085796,
		502808522,
		3510232957,
		4110872784,
		1610999079,
		46490781,
		2800056901,
		4011062378,
		1044255839,
		3569961745,
		2978339588,
		409218562,
		2066803535,
		3961636608,
		1770360963,
		3710603844,
		995437140,
		2636890895,
		3538868507,
		2509882552,
		587402334,
		4191982384,
		652021293,
		1294109346,
		2212402150,
		4050272082,
		1587872446,
		1038597010,
		403074935,
		3265934777,
		2274187315,
		2469137435,
		1686625182,
		1372973719,
		3101821069,
		104050036,
		3891077994,
		3763716061,
		2703517795,
		865308896,
		2473335356,
		2690609466,
		2106935771,
		2197823014,
		3872460941,
		3183500076,
		3596535477,
		2517425827,
		1475060233,
		3083214127,
		3851694499,
		3046181248,
		803085575,
		1055315367,
		585727316,
		4048883253,
		1437537224,
		3454542398,
		536481877,
		2541717191,
		577089374,
		2516557656,
		2801812380,
		979417983,
		310860960,
		3909264458,
		684069606,
		2325787328,
		3844200896,
		3870995802,
		166343244,
		3557994078,
		2107907651,
		823132823,
		3420593844,
		2870314571,
		2407243096,
		337753816,
		2100855961,
		3011314628,
		1798300530,
		3745830452,
		1022065912,
		4007435547,
		4245461732,
		689783190,
		1465544341,
		2930176444,
		1417462986,
		3854566168,
		4277082419,
		1210477706,
		3268308011,
		2654483574,
		2813473597,
		3114402267,
		3233601138,
		3603210040,
		3647692844,
		1098909387,
		2881032083,
		69468944,
		2526640894,
		2731894602,
		696234818,
		1091276784,
		2625969831,
		1963336334,
		556169814,
		3511542247,
		1160903930,
		3938779342,
		104332225,
		72037293,
		308192449,
		2354128425,
		3686092657,
		1515509605,
		110632845,
		2931884567,
		4150656210,
		3626294451,
		3626474712,
		2210489662,
		4102544429,
		372138682,
		3998073964,
		4071702342,
		2441134968,
		592868251,
		2589598097,
		1396436982,
		1212923685,
		4218881199,
		3435051145,
		1388196162,
		3114722757,
		2427726998,
		908087146,
		347762200,
		1677706645,
		283877779,
		2986252306,
		3221524384,
		2335836593,
		2589815575,
		3569795192,
		2271797742,
		2345764860,
		2282028012,
		3493727166,
		2920741138,
		3478614119,
		3933892876,
		3998446774,
		3275141493,
		636016287,
		1428825056,
		4254877514,
		3204028461,
		1531910035,
		3213840415,
		2987598994,
		321298578,
		1120196893,
		2139954912,
		1311559859,
		1811075992,
		3038247907,
		39145533,
		1655892874,
		947711505,
		380711513,
		3796971281,
		2172599740,
		1949927728,
		368474752,
		2666365566,
		769055321,
		853777908,
		3147366098,
		519923905,
		2505406287,
		1266953847,
		1614300674,
		2167160675,
		612716203,
		2483868189,
		3000616608,
		3293473656,
		219091937,
		464109097,
		2582556861,
		1552504365,
		1790667848,
		721047414,
		1428008661,
		2290129015,
		1374159432,
		3359661036,
		1503540477,
		2426304890,
		4080513446,
		2304313062,
		583241280,
		2053229213,
		1009412470,
		780106692,
		380041287,
		3396514635,
		3843863958,
		584735186,
		2695063305,
		3874558324,
		1873312635,
		2574466107,
		2730783164,
		2415745999,
		917244338,
		1238280351,
		67651390,
		4102244164,
		646906818,
		2603432318,
		1627159818,
		1464776838,
		4285222156,
		236511956,
		2264182407,
		1057272760,
		3863720689,
		1938205582,
		945395926,
		4181719629,
		2738372412,
		7354857,
		1085655044,
		2189169832,
		2955482909,
		1233479129,
		2436095738,
		3156063073,
		1411977135,
		704554764,
		949274274,
		2555713172,
		2150552210,
		3681149489,
		1662772579,
		2096295067,
		3626073933,
		451769422,
		1555515119,
		3511057702,
		4260912945,
		1274910497,
		2822060100,
		1457747377,
		460066336,
	}
	mt := NewMT(1131464071)
	for i, want := range nums {
		if got := mt.Uint32(); got != want {
			t.Fatalf("got %v (output #%v), want %v", got, i+1, want)
		}
	}
}

func TestClone(t *testing.T) {
	mt1 := NewMT(uint32(time.Now().Unix()))
	mt2 := Clone(mt1)
	for i := 0; i < 700; i++ {
		want := mt1.Uint32()
		if got := mt2.Uint32(); got != want {
			t.Fatalf("got %v (output #%v), want %v", got, i+1, want)
		}
	}
}

func TestUntemper(t *testing.T) {
	mt := NewMT(uint32(time.Now().Unix()))
	for i := 0; i < 100; i++ {
		want := mt.Uint32()
		if got := Untemper(temper(want)); got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

func TestBitMask(t *testing.T) {
	cases := []struct {
		i, j int
		want uint32
	}{
		{
			0,
			31,
			^uint32(0),
		},
		{
			31,
			31,
			uint32(1),
		},
		{
			28,
			30,
			uint32(14),
		},
	}
	for _, c := range cases {
		if got := BitMask(c.i, c.j); got != c.want {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}
