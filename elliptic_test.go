package ed448

import (
	"crypto/elliptic"
	"math/big"

	. "gopkg.in/check.v1"
)

func (s *Ed448Suite) Test_IsValidMontgomeryPoint(c *C) {
	curve448 := Curve448()
	c.Assert(curve448.IsOnCurve(curve448.Params().Gx, curve448.Params().Gy), Equals, true)

	x, y := new(big.Int).SetInt64(1), new(big.Int).SetInt64(1)
	c.Assert(curve448.IsOnCurve(x, y), Equals, false)
}

func (s *Ed448Suite) Test_AddMontgomeryPoint(c *C) {
	curve448 := Curve448()
	x, y := curve448.Add(curve448.Params().Gy, curve448.Params().Gx, curve448.Params().Gy, curve448.Params().Gx)

	c.Assert(curve448.IsOnCurve(x, y), Equals, false)

	x1, y1 := new(big.Int).SetInt64(0), new(big.Int).SetInt64(0)
	baseX := curve448.Params().Gy
	baseY := curve448.Params().Gx

	x3, y3 := curve448.Add(baseX, baseY, x1, y1)
	c.Assert(x3, DeepEquals, baseX)
	c.Assert(y3, DeepEquals, baseY)

	x2, y2 := new(big.Int).SetInt64(0), new(big.Int).SetInt64(1)
	x4, y4 := curve448.Add(baseX, baseY, x2, y2)
	c.Assert(x4, DeepEquals, baseX)
	c.Assert(y4, DeepEquals, baseY)

	x5, y5 := new(big.Int), new(big.Int)

	x5, _ = new(big.Int).SetString("4", 10)
	y5, _ = new(big.Int).SetString("726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439", 10)

	x6, y6 := curve448.Add(baseX, baseY, x5, y5)
	x7, y7 := curve448.Add(x5, y5, baseX, baseY)
	c.Assert(x6, DeepEquals, x7)
	c.Assert(y6, DeepEquals, y7)

	x8, y8, x9, y9, expX, expY := new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	x8, _ = new(big.Int).SetString("433443361598748394701417986575928357546763661203117600043232905000028761071719406246348643379321363838866504985224564572770226765990586", 10)
	y8, _ = new(big.Int).SetString("378180796090612387484360060167085690663268050333018267799833971554607723925592025315474002723386943182362017106553352753245947895743479", 10)
	x9, _ = new(big.Int).SetString("382850781097090663709435269669640128413917424161161996541369885313135463250598457117281855634894229940922432611115644924040039102503234", 10)
	y9, _ = new(big.Int).SetString("150032120648431757022042238756625299463102532040077213041923799066134940898180505548999694411382133856991713245174259454210400718782657", 10)
	expX, _ = new(big.Int).SetString("129047869882856584959883465255673139377652618615517752505987429739580823634020523714192642986568304850190649515452739028807588827562583", 10)
	expY, _ = new(big.Int).SetString("13236954042666348090796368258501804732257529313063044842010831108362828670295816335182937585615704980797353229964943156848621844171415", 10)

	x10, y10 := curve448.Add(x9, y9, x8, y8)
	c.Assert(x10, DeepEquals, expX)
	c.Assert(y10, DeepEquals, expY)

	x11, y11, x12, y12, expX, expY := new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	x11, _ = new(big.Int).SetString("186018839615507079413199093070717592812002119873418173593916393111792085969434229041082586709013639780490201665900635752725798809408980", 10)
	y11, _ = new(big.Int).SetString("275478055601171243947527028947020371185249228097593994340456984823789305324789691316762161313297666484661547434924334319480485887694066", 10)
	x12, _ = new(big.Int).SetString("413897749260189723589717807776392776719827889509246437342956270719240163503092605659271474847110716843903339867756336722050920427064187", 10)
	y12, _ = new(big.Int).SetString("305093327566709600303106874973393232619240864134105903820050919938034603530073121675497262449523954591240562252908752672536761026426011", 10)
	expX, _ = new(big.Int).SetString("725215688262707777034914854950081789303097835115207774892072244909770811531391488638746485079627787690169675359006010307967059337892854", 10)
	expY, _ = new(big.Int).SetString("678412379217939073601968192027284179427052531119812553631033252634805082762251604756255174894387074571726460008801291297401785405309262", 10)

	x13, y13 := curve448.Add(x11, y11, x12, y12)
	c.Assert(x13, DeepEquals, expX)
	c.Assert(y13, DeepEquals, expY)
}

func (s *Ed448Suite) Test_DoubleMontgomeryPoint(c *C) {
	curve448 := Curve448()
	x1, y1 := new(big.Int).SetInt64(0), new(big.Int).SetInt64(0)
	x, y := curve448.Double(x1, y1)

	c.Assert(x.Sign(), Equals, 0)
	c.Assert(y.Sign(), Equals, 0)

	x2, y2 := new(big.Int), new(big.Int)
	x2, _ = new(big.Int).SetString("4", 10)
	y2, _ = new(big.Int).SetString("726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439", 10)

	x3, y3 := curve448.Add(x2, y2, x2, y2)
	x4, y4 := curve448.Double(x2, y2)

	c.Assert(x3, DeepEquals, x4)
	c.Assert(y3, DeepEquals, y4)

	x5, y5, expX, expY := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	x5, _ = new(big.Int).SetString("48360777981867934796535616536755706621987516464591679425049903238038070274256423958555032696911873506872608262863489084597145204512125", 10)
	y5, _ = new(big.Int).SetString("431104697797966958720005333026209965480281767528850739356107182584052888170735123069159175440775654980565720535419111799925838359882201", 10)
	expX, _ = new(big.Int).SetString("113630863301784633715172637082174938990638542527692747643853767687397205840631442036588982197580891611871811467915834686935421239342141", 10)
	expY, _ = new(big.Int).SetString("676641884739058461262866875739288191407043898149425100308014541941940188547418765050301732193528185729567185470472148061706681481506152", 10)

	x6, y6 := curve448.Double(x5, y5)
	c.Assert(x6, DeepEquals, expX)
	c.Assert(y6, DeepEquals, expY)
}

func (s *Ed448Suite) Test_ToWeierstrass(c *C) {
	curve448 := Curve448()
	x1, y1 := new(big.Int), new(big.Int)
	x1, _ = new(big.Int).SetString("231377890921338904518205299856376721703219563117283983079958269601060265976904425361145529045960144400058309398699153649002423548298720", 10)
	y1, _ = new(big.Int).SetString("396470232851935653847228280278763393516978080823452257000621302374855114122620731407610347464119182030967456725173634988669847746509756", 10)

	x, y, z := ToWeierstrassCurve(curve448.Params().P, x1, y1)

	x2, y2, z2 := new(big.Int), new(big.Int), new(big.Int)

	x2, _ = new(big.Int).SetString("231377890921338904518205299856376721703219563117283983079958269601060265976904425361145529045960144400058309398699153649002423548298720", 10)
	y2, _ = new(big.Int).SetString("396470232851935653847228280278763393516978080823452257000621302374855114122620731407610347464119182030967456725173634988669847746509756", 10)
	z2, _ = new(big.Int).SetString("1", 10)

	c.Assert(x, DeepEquals, x2)
	c.Assert(y, DeepEquals, y2)
	c.Assert(z, DeepEquals, z2)
}

func (s *Ed448Suite) Test_ScalarMultDoubleAndAdd(c *C) {
	curve448 := Curve448()
	x1, y1 := new(big.Int), new(big.Int)
	sc := new(big.Int)
	expX, expY := new(big.Int), new(big.Int)

	x1, _ = new(big.Int).SetString("93263703393751592515478201276933079199455049245242592062494239004476886639532093656348784063507832781248069774337081703799296825273157", 10)
	y1, _ = new(big.Int).SetString("65701948784024482812892259655089014209694971103718051260428416600571273565015409766085362758944216286160311778933871167199117608686980", 10)
	sc, _ = new(big.Int).SetString("4", 10)
	expX, _ = new(big.Int).SetString("202153740723611312197845507678411660974244296583955638161232971272192732225435060449944711905797274457545133479527608333145847731966299", 10)
	expY, _ = new(big.Int).SetString("608729637406846025943737458918089555834435648073468703454221404283312533595985092348819448481226213984423813097591564490475313441415967", 10)

	x2, y2 := curve448.ScalarMult(x1, y1, sc.Bytes())

	c.Assert(x2, DeepEquals, expX)
	c.Assert(y2, DeepEquals, expY)

	x3, y3 := new(big.Int), new(big.Int)

	x3, _ = new(big.Int).SetString("573788225295558688949924467693518872971875191714037286216177810579067974204134280938061184135956022645079167516387390631464769881281360", 10)
	y3, _ = new(big.Int).SetString("255021125439662423819140291206355809810685652305921521554592817915688478854567589768741366548971257758237240772118105381941870236247910", 10)
	sc, _ = new(big.Int).SetString("4", 10)
	expX, _ = new(big.Int).SetString("194883264699157211378948890318315607750282590143444800641798305076683669615143598784608144151424077384322793523414446065607279057090040", 10)
	expY, _ = new(big.Int).SetString("330832701313571564112586130166073415672337809353116341040436629551529804299536605944003724879925210570782576473500393484348406130386509", 10)

	x4, y4 := curve448.ScalarMult(x3, y3, sc.Bytes())

	c.Assert(x4, DeepEquals, expX)
	c.Assert(y4, DeepEquals, expY)

	x5, y5 := new(big.Int), new(big.Int)

	x5, _ = new(big.Int).SetString("566042578825885580488047601917875437969596115217986651179927085074474619280114341277418732495030511657177971580157079735153033683461508", 10)
	y5, _ = new(big.Int).SetString("708909118268548743964115180881094751119939429853421661061770012160066658890789723329656242491499563157905960621134553343773534994960196", 10)
	sc, _ = new(big.Int).SetString("4", 10)
	expX, _ = new(big.Int).SetString("57288601386672893407874879257662617319706821826107369944743051940501128048648387784449665015295226632601314952547741509893923162403136", 10)
	expY, _ = new(big.Int).SetString("489868081629990339309772086826537501394285364015056133577630249083776727623092492539092473930151322368883152536487886009666038872268558", 10)

	x6, y6 := curve448.ScalarMult(x5, y5, sc.Bytes())

	c.Assert(x6, DeepEquals, expX)
	c.Assert(y6, DeepEquals, expY)

	x7, y7 := new(big.Int), new(big.Int)

	x7, _ = new(big.Int).SetString("632142126624648232073337033972619430599389710657671550583527530913282263058441414567664554122119306777036565766082563417659084381572185", 10)
	y7, _ = new(big.Int).SetString("384573752687036348452408169242450138534709238241365288294060425206124973092981280082817270148866264097109579806560291184264296596034340", 10)
	sc, _ = new(big.Int).SetString("181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779", 10)
	expX, _ = new(big.Int).SetString("0", 10)
	expY, _ = new(big.Int).SetString("1", 10)

	x8, y8 := curve448.ScalarMult(x7, y7, sc.Bytes())

	c.Assert(x8, DeepEquals, expX)
	c.Assert(y8, DeepEquals, expY)

	x9, y9 := new(big.Int), new(big.Int)

	x9, _ = new(big.Int).SetString("304477079363602618815469769235945795998975779049240203892874506068725781518739537180562934445071759525143979293123759454933404762014195", 10)
	y9, _ = new(big.Int).SetString("154794821346395464793269903329267276134700978731354217949891735706363598980486622922944913474076867281043481856665408397918798972354562", 10)
	sc, _ = new(big.Int).SetString("181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779", 10)
	expX, _ = new(big.Int).SetString("0", 10)
	expY, _ = new(big.Int).SetString("1", 10)

	x10, y10 := curve448.ScalarMult(x9, y9, sc.Bytes())

	c.Assert(x10, DeepEquals, expX)
	c.Assert(y10, DeepEquals, expY)
}

// With RFC7748 test vectors
func (s *Ed448Suite) Test_ScalarMultMontgomeryPoint(c *C) {
	curve448 := Curve448()
	x1 := new(big.Int)
	sc := new(big.Int)
	exp := new(big.Int)

	x1, _ = new(big.Int).SetString("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086", 16)
	sc, _ = new(big.Int).SetString("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3", 16)
	y1 := new(big.Int).SetInt64(0)
	exp, _ = new(big.Int).SetString("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f", 16)

	dst, _ := LadderScalarMult(curve448, x1, y1, sc.Bytes())

	c.Assert(dst.Bytes(), DeepEquals, exp.Bytes())

	x1, _ = new(big.Int).SetString("0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db", 16)
	sc, _ = new(big.Int).SetString("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f", 16)
	exp, _ = new(big.Int).SetString("884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d", 16)

	dst, _ = LadderScalarMult(curve448, x1, y1, sc.Bytes())

	c.Assert(dst.Bytes(), DeepEquals, exp.Bytes())

	x1, _ = new(big.Int).SetString("ed4b975a7964dae724b8db5c141f2f99a6f02d0898c32c8fa2c0f2f606d130a2aed16df4a1531ce17dd101c17e4d3ee7408407f1d3e3bbdb", 16)
	y1, _ = new(big.Int).SetString("241605407a32be448d0f8b9c56b78f4fd9dd4ff8593ce8a564e89d6f3a1d5e902f1fa0e7ac4fb797e628c8cfbb3bf1d84472ccf1eb39f810", 16)
	sc, _ = new(big.Int).SetString("4", 16)
	exp = new(big.Int).SetBytes(
		[]byte{
			0xa9, 0x6b, 0x59, 0x60, 0x13, 0x59, 0x02, 0xd8,
			0xe5, 0x41, 0xba, 0x79, 0x2d, 0xeb, 0x88, 0xab,
			0x90, 0x2d, 0x2d, 0x33, 0x69, 0xbe, 0x54, 0xee,
			0x33, 0x54, 0x6b, 0x9a, 0xfe, 0x32, 0x14, 0x75,
			0xe7, 0xc4, 0x9a, 0x6c, 0x5e, 0xd5, 0xdb, 0x3f,
			0x06, 0xda, 0x13, 0xc1, 0x1e, 0xc8, 0xe8, 0xc7,
			0x44, 0x37, 0x66, 0x3e, 0x31, 0x13, 0x95, 0x08,
		})
	dst, _ = LadderScalarMult(curve448, x1, y1, sc.Bytes())

	c.Assert(dst.Bytes(), DeepEquals, exp.Bytes())
}

// With RFC7748 test vectors
func (s *Ed448Suite) Test_ScalarBaseMultMontgomeryPoint(c *C) {
	curve448 := Curve448()
	sc := new(big.Int)
	exp := new(big.Int)

	sc, _ = new(big.Int).SetString("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b", 16)
	exp, _ = new(big.Int).SetString("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0", 16)

	dst, _ := LadderScalarBaseMult(curve448, sc.Bytes())

	c.Assert(dst.Bytes(), DeepEquals, exp.Bytes())

	sc, _ = new(big.Int).SetString("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d", 16)
	exp, _ = new(big.Int).SetString("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609", 16)

	dst, _ = LadderScalarBaseMult(curve448, sc.Bytes())

	c.Assert(dst.Bytes(), DeepEquals, exp.Bytes())
}

func (s *Ed448Suite) Test_MapToCurve(c *C) {
	P, _ := new(big.Int).SetString("726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439", 10)
	N, _ := new(big.Int).SetString("181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779", 10)
	A, _ := new(big.Int).SetString("156326", 10)
	Gu, _ := new(big.Int).SetString("5", 10)
	Gv, _ := new(big.Int).SetString("355293926785568175264127502063783334808976399387714271831880898435169088786967410002932673765864550910142774147268105838985595290606362", 10)
	curve448 = &CurveParams{&elliptic.CurveParams{Name: "curve-448",
		P:       P,
		N:       N,
		B:       A,
		Gx:      Gu,
		Gy:      Gv,
		BitSize: 448,
	}}

	u := new(big.Int).SetInt64(0)
	x, y := new(big.Int), new(big.Int)

	for i := 0; i < 52; i++ {
		x, y = curve448.MapToCurve(u)
		c.Assert(curve448.IsOnCurve(x, y), Equals, true)
		u.Add(u, new(big.Int).SetInt64(1))
	}
}

func (s *Ed448Suite) Test_Curve25519Params(c *C) {
	curve25519 := CurveP25519()
	Gv, _ := new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)
	c.Assert(curve25519.Params().P, DeepEquals, Gv)

}

func (s *Ed448Suite) Test_IsValidMontgomery25519Point(c *C) {
	curve25519 := CurveP25519()
	c.Assert(curve25519.IsOnCurve(curve25519.Params().Gx, curve25519.Params().Gy), Equals, true)
}
