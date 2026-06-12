use std::sync::Mutex;

/// Calculates Greatest Common Divisor
#[allow(clippy::many_single_char_names)]
const fn calc_gcd(mut x: isize, mut y: isize) -> isize {
    if x == 0 {
        return y;
    }

    if y == 0 {
        return x;
    }

    while y != 0 {
        let t = x % y;
        x = y;
        y = t;
    }

    x
}

#[derive(Debug)]
struct WrrCounters {
    i: isize,
    curr_weight: isize,
}

/// Implementation of Weighted Round Robin algorithm.
/// Based on http://kb.linuxvirtualserver.org/wiki/Weighted_Round-Robin_Scheduling
///
/// TODO: move it to `ic-bn-lib` as a generic version and replace one that is used in Distributor there.
#[derive(Debug)]
pub struct Wrr<T> {
    items: Vec<(usize, T)>,
    n: isize,
    gcd: isize,
    max_weight: isize,
    counters: Mutex<WrrCounters>,
}

impl<T> Wrr<T> {
    pub fn new(items: Vec<(usize, T)>) -> Self {
        let mut gcd = 0;
        let mut max_weight = 0;

        for v in &items {
            let w = v.0.cast_signed();
            gcd = calc_gcd(gcd, w);

            if w > max_weight {
                max_weight = w;
            }
        }

        Self {
            n: items.len().cast_signed(),
            items,
            gcd,
            max_weight,
            counters: Mutex::new(WrrCounters {
                i: -1,
                curr_weight: 0,
            }),
        }
    }

    /// Returns a reference to the next item according to weights
    pub fn next(&self) -> &T {
        let mut c = self.counters.lock().unwrap();

        loop {
            c.i = (c.i + 1) % self.n;
            if c.i == 0 {
                c.curr_weight -= self.gcd;
                if c.curr_weight <= 0 {
                    c.curr_weight = self.max_weight;
                }
            }

            if (self.items[c.i.cast_unsigned()].0.cast_signed()) >= c.curr_weight {
                return &self.items[c.i.cast_unsigned()].1;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use ahash::AHashMap;

    use super::*;

    #[test]
    fn test_wrr() {
        let items = vec![
            (2, "foo".to_string()),
            (3, "bar".to_string()),
            (5, "baz".to_string()),
        ];

        let wrr = Wrr::new(items);
        let mut hits = AHashMap::new();

        // Do 1k selections
        for _ in 0..1000 {
            let item = wrr.next();
            hits.entry(item.clone())
                .and_modify(|x| *x += 1)
                .or_insert(1);
        }

        // Make sure that we get the distribution according to the weights
        assert_eq!(hits["foo"], 200);
        assert_eq!(hits["bar"], 300);
        assert_eq!(hits["baz"], 500);
    }
}
