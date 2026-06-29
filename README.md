 * Domain Availability Checker
 * 支持单域名查询和批量扫描
 *
 * 单域名查询:
 *   php run.php google.com
 *
 * 批量扫描:
 *   php run.php                           # 4字母.com (aaaa~zzzz)
 *   php run.php --length=3                # 3字母
 *   php run.php --length=4 --batch=100    # 每批并发100个
 *   php run.php --length=4 --tld=xyz      # .xyz后缀
 */
