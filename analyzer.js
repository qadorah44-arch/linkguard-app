(function () {
  let DB = null;

  async function load(path = "threats.json") {
    try {
      const res = await fetch(path);
      DB = await res.json();
    } catch (e) {
      console.error("تعذر تحميل قاعدة البيانات", e);
      DB = { blockedDomains: [], blockedIPs: [], suspiciousTlds: [], shorteners: [], phishingKeywords: [], brands: {} };
    }
    return DB;
  }

  function analyze(input) {
    if (!DB) throw new Error("استدعِ LinkGuard.load() أولًا");
    let raw = String(input || "").trim();
    if (!raw) return { score: 0, level: "safe", label: "أدخل رابطًا", reasons: [] };
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = "http://" + raw;

    let u;
    try { u = new URL(raw); } catch (e) {
      return { score: 100, level: "danger", label: "رابط غير صالح", reasons: ["صيغة الرابط غير صحيحة"] };
    }

    const host = u.hostname.toLowerCase();
    const full = raw.toLowerCase();
    const reasons = [];
    let score = 0;
    const add = (pts, why) => { score += pts; reasons.push(why); };

    const parts = host.split(".");
    let listed = (DB.blockedIPs || []).includes(host);
    for (let i = 0; !listed && i < parts.length - 1; i++) {
      if (DB.blockedDomains.includes(parts.slice(i).join("."))) listed = true;
    }
    if (listed) add(100, "موجود في قاعدة بيانات URLhaus للروابط الضارة");

    if (u.protocol !== "https:") add(15, "الرابط لا يستخدم HTTPS");
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add(30, "الرابط يستخدم عنوان IP بدل اسم نطاق");
    if (host.includes("xn--")) add(25, "النطاق يحتوي رموزًا مموّهة (Punycode)");
    if (full.includes("@")) add(25, "الرابط يحتوي على رمز @ لإخفاء الوجهة الحقيقية");
    if (parts.length > 4) add(15, "عدد كبير من النطاقات الفرعية");
    if ((host.match(/-/g) || []).length >= 3) add(10, "شرطات كثيرة في اسم النطاق");
    if ((host.match(/\d/g) || []).length >= 4) add(10, "أرقام كثيرة في اسم النطاق");
    if (raw.length > 100) add(10, "الرابط طويل بشكل غير معتاد");

    const tld = parts[parts.length - 1];
    if (DB.suspiciousTlds.includes(tld)) add(15, "امتداد النطاق ." + tld + " كثير الاستخدام في الاحتيال");
    if (DB.shorteners.includes(host)) add(15, "رابط مختصر يخفي الوجهة الحقيقية");

    const hits = DB.phishingKeywords.filter(k => (host + u.pathname).includes(k));
    if (hits.length) add(Math.min(hits.length * 10, 30), "كلمات تصيّد: " + hits.slice(0, 4).join("، "));

    for (const [brand, domains] of Object.entries(DB.brands)) {
      const real = domains.some(d => host === d || host.endsWith("." + d));
      if (host.includes(brand) && !real) {
        add(35, "ينتحل اسم " + brand + " وهو ليس نطاقه الرسمي");
        break;
      }
    }

    score = Math.min(score, 100);
    const level = score >= 55 ? "danger" : score >= 25 ? "warn" : "safe";
    const label = { safe: "يبدو آمنًا", warn: "مشبوه", danger: "خطير" }[level];
    if (!reasons.length) reasons.push("لم نجد مؤشرات خطر واضحة");
    return { score, level, label, host, reasons };
  }

  window.LinkGuard = { load, analyze };
})();
