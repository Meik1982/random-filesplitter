# RFS-Matrix: General Access Linear Secret Sharing & Multi-Payload Decoys über $\mathbb{F}_2$

**Autor:** Meik Augenblick  
**Projekt:** Random File Splitter (`rfs`)  
**Status:** Architekturspezifikation & formaler informationstheoretischer Beweis (Stufe 8)  
**Ziel:** Lineares Secret-Sharing-Verfahren (LSSS) über dem Galois-Körper $\mathbb{F}_2$

---

## 1. Motivation & Vision

Klassische $N$-aus-$N$ File-Splitter erzwingen eine starre Alles-oder-Nichts-Schwelle: Exakt alle $N$ Teile müssen vorliegen, um das Geheimnis zu rekonstruieren ($P = C_1 \oplus \dots \oplus C_N$). Obwohl diese Topologie informationstheoretisch perfekt ist, stößt sie an Grenzen, wenn mehrere Parteien abgestufte Zugriffsrechte besitzen oder wenn zur glaubhaften Abstreitbarkeit (**Plausible Deniability**) mehrere unabhängige Nutzdaten (echte Geheimnisse und harmlose Köder) im **exakt selben Pool von Shares** koexistieren sollen.

**RFS-Matrix** verallgemeinert die One-Time-Pad-Kette auf beliebige **monotone Zugriffsstrukturen** $\Gamma$ über dem endlichen Körper $\mathbb{F}_2 = (\{0, 1\}, \oplus, \cdot)$.

Aus einem gemeinsamen Pool von $M$ Shares $\{C_1, \dots, C_M\}$ enthüllen unterschiedliche Teilmengen völlig unterschiedliche, kryptografisch verifizierte Nutzdaten – ohne gegenseitige Informationslecks:
* **Teilmenge $A = \{C_1, C_3, C_7\} \longrightarrow$ Echtes Hauptgeheimnis** (z. B. Master-Datenbank, BLKS-384 geprüft).
* **Teilmenge $B = \{C_1, C_2, C_3\} \longrightarrow \text{Köder}_0$** (z. B. Steuererklärung, BLKS-384 geprüft).
* **Teilmenge $C = \{C_2, C_3, C_9\} \longrightarrow \text{Köder}_1$** (z. B. Urlaubsbilder, BLKS-384 geprüft).
* **Teilmenge $D = \{C_4, C_5, C_7\} \longrightarrow \text{Köder}_2$** (z. B. Linux Kernel Quelltext ISO, BLKS-384 geprüft).
* **Jede unautorisierte Teilmenge $\longrightarrow$ Reines Pseudozufallsrauschen** (Shannon-Entropie $H \ge 7{,}9998$).

---

## 2. Mathematische Formalisierung über $\mathbb{F}_2$

### 2.1 Der Basisraum
Sei $L$ die Bytegröße jeder Share (ausgerichtet an 4-KiB-Clustergrenzen).
Wir definieren:
1. $R$ unabhängige, gleichverteilte Zufalls-Basisströme:
   $$\vec{b}_1, \vec{b}_2, \dots, \vec{b}_R \in \{0, 1\}^L \quad \text{mit } \vec{b}_j \sim \mathcal{U}(\{0, 1\}^L)$$
   erzeugt via ChaCha20, gespeist aus physischer Systementropie.
2. $K$ unabhängige Nutzdatenströme (Geheimnisse und Köder):
   $$\vec{p}_1, \vec{p}_2, \dots, \vec{p}_K \in \{0, 1\}^L$$

### 2.2 Share-Synthese über lineare Generatormatrizen
Jede Share $C_i$ ($1 \le i \le M$) wird als Linearkombination in $\mathbb{F}_2$ gebildet:
$$C_i = \bigoplus_{j=1}^R G_{i,j} \vec{b}_j \oplus \bigoplus_{k=1}^K H_{i,k} \vec{p}_k$$

In Matrixschreibweise über $\mathbb{F}_2$:
$$\mathbf{C} = \mathbf{G} \mathbf{B} \oplus \mathbf{H} \mathbf{P}$$
wobei:
* $\mathbf{C} \in \mathbb{F}_2^{M \times L}$ die $M$ erzeugten Share-Dateien darstellt.
* $\mathbf{G} \in \mathbb{F}_2^{M \times R}$ die **Zufallsbasis-Generatormatrix** ist.
* $\mathbf{B} \in \mathbb{F}_2^{R \times L}$ die $R$ unabhängigen ChaCha20-Zufallsströme enthält.
* $\mathbf{H} \in \mathbb{F}_2^{M \times K}$ die **Nutzdaten-Kodierungsmatrix** ist.
* $\mathbf{P} \in \mathbb{F}_2^{K \times L}$ die $K$ gepolsterten Nutzdatenströme enthält.

### 2.3 Rekonstruktionskriterium
Eine Zugriffsanfrage wird durch einen Indikatorvektor $\vec{x} \in \mathbb{F}_2^M$ dargestellt, wobei $x_i = 1$ das Vorhandensein von Share $C_i$ anzeigt und $x_i = 0$ das Fehlen.

Die Rekonstruktion ist die bitweise SIMD-XOR-Summe der ausgewählten Shares:
$$R(\vec{x}) = \vec{x}^T \mathbf{C} = (\vec{x}^T \mathbf{G}) \mathbf{B} \oplus (\vec{x}^T \mathbf{H}) \mathbf{P}$$

Damit Teilmenge $\vec{x}$ ausschließlich und fehlerfrei die Nutzlast $\vec{p}_k$ ($1 \le k \le K$) rekonstruiert, **müssen folgende zwei Bedingungen über $\mathbb{F}_2$ simultan erfüllt sein**:

1. **Rausch-Auslöschungsbedingung (Noise Annihilation):**
   $$\vec{x}^T \mathbf{G} = \vec{0}^T \in \mathbb{F}_2^{1 \times R}$$
   *(Alle Zufallsbasisvektoren heben sich durch additive XOR-Inversion exakt zu Null auf).*

2. **Orthogonale Nutzdaten-Isolation:**
   $$\vec{x}^T \mathbf{H} = \vec{e}_k^T \in \mathbb{F}_2^{1 \times K}$$
   wobei $\vec{e}_k$ der $k$-te Standard-Einheitsbasisvektor in $\mathbb{F}_2^K$ ist.
   *(Nutzlast $k$ besitzt den Koeffizienten 1; alle anderen $K-1$ Nutzdatenströme werden mit Koeffizient 0 ausgelöscht).*

Sind beide Bedingungen erfüllt, gilt:
$$R(\vec{x}) = \vec{0} \cdot \mathbf{B} \oplus \vec{e}_k^T \mathbf{P} = \vec{p}_k$$

---

## 3. Informationstheoretischer Sicherheitsbeweis (Zero-Leakage-Theorem)

### Theorem 1 (Shannon Perfect Secrecy für unvollständige Teilmengen)
*Sei $\vec{y} \in \mathbb{F}_2^M$ ein unautorisierter Teilmengen-Indikatorvektor, für den $\vec{y}^T \mathbf{G} \ne \vec{0}^T$ gilt. Dann ist die Transinformation (Mutual Information) zwischen dem rekonstruierten Datenstrom $\vec{y}^T \mathbf{C}$ und jeder beliebigen Nutzlast $\vec{p}_k$ identisch Null:*
$$I(\vec{p}_k ; \vec{y}^T \mathbf{C}) = 0$$

### Beweis:
1. Da $\vec{y}^T \mathbf{G} \ne \vec{0}^T$, existiert mindestens ein Index $j^* \in \{1, \dots, R\}$ mit $(\vec{y}^T \mathbf{G})_{j^*} = 1$.
2. Der rekonstruierte Datenstrom lässt sich partitionieren in:
   $$\vec{y}^T \mathbf{C} = \vec{b}_{j^*} \oplus \vec{Z}$$
   wobei $\vec{Z} = \bigoplus_{j \ne j^*} (\vec{y}^T \mathbf{G})_j \vec{b}_j \oplus (\vec{y}^T \mathbf{H}) \mathbf{P}$.
3. Gemäß Konstruktion ist $\vec{b}_{j^*}$ eine gleichverteilte Zufallsvariable über $\{0, 1\}^L$, statistisch unabhängig von allen anderen Basisvektoren $\vec{b}_{j}$ ($j \ne j^*$) und unabhängig von allen Klartexten $\mathbf{P}$.
4. Nach Shannons One-Time-Pad-Lemma (Shannon, 1949):  
   Ist $B \sim \mathcal{U}(\{0, 1\}^L)$ unabhängig von einer beliebigen Zufallsvariablen $Z$, so ist auch $B \oplus Z \sim \mathcal{U}(\{0, 1\}^L)$ gleichverteilt und statistisch unabhängig von $Z$.
5. Folglich gilt für die bedingte Entropie:
   $$H(\vec{y}^T \mathbf{C} \mid \mathbf{P}) = H(\vec{y}^T \mathbf{C}) = L \cdot \log_2(2) = L \text{ Bits}$$
6. Die Transinformation verschwindet:
   $$I(\mathbf{P} ; \vec{y}^T \mathbf{C}) = H(\vec{y}^T \mathbf{C}) - H(\vec{y}^T \mathbf{C} \mid \mathbf{P}) = L - L = 0$$
   $\blacksquare$

**Kryptografische Konsequenz:**  
Selbst ein Angreifer mit unendlicher Quantenrechenleistung kann aus einer unvollständigen Teilmenge nicht ein einziges Bit über ein Geheimnis oder einen Köder ableiten. Die empfangenen Bytes sind informationstheoretisch ununterscheidbar von physikalischem Rauschen.

---

## 4. Automatisierte Matrix-Solver via Gauß-Jordan über $\mathbb{F}_2$

Zur automatisierten Berechnung konsistenter Matrizen $\mathbf{G}$ und $\mathbf{H}$ implementiert der RFS-Compiler die **Gauß-Jordan-Elimination über $\mathbb{F}_2$**.

### 4.1 Bit-parallele Algebra
In Rust werden Vektoren über $\mathbb{F}_2$ mit $M \le 64$ direkt auf 64-Bit Integern (`u64`) abgebildet:
* Vektor-Addition ($a \oplus b$) $\longrightarrow$ `a ^ b`
* Skalar-Multiplikation ($a \cdot b$) $\longrightarrow$ `a & b`
* Zeilenreduktion $\longrightarrow$ `row[i] ^= row[pivot]` (in einem einzigen Taktzyklus).

---

## 5. Multi-Target Stealth-Trailer Kodierung

Eine Kernherausforderung bei Deniable-Matrix-Verfahren ist die **Metadaten-Isolation**: Wie erkennt `rfs scan` oder `rfs restore`, welche Teilmenge welche Datei ergibt, ohne eine verräterische globale Metadatentabelle zu hinterlassen?

### Das XOR-Superpositions-Trailer-Muster
Jede Share endet auf einen 64-Byte Stealth-Trailer:
$$\text{Tail}_i = \text{Share}_i[L-64 \dots L]$$

Für jede autorisierte Zugriffskombination $\vec{x}_k = \{i_1, \dots, i_m\}$ für Nutzlast $k$ gilt:
$$\bigoplus_{i \in \vec{x}_k} \text{Tail}_i = \text{Trailer}(P_k)$$

wobei $\text{Trailer}(P_k)$ den validen `RFS4`-Magic-Tag, die Originalgröße, den BLKS-384 Hash und die Dateinamenlänge enthält. Unautorisierte Kombinationen ergeben unkorreliertes Zufallsrauschen ohne Magic-Tag.
